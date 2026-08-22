#import <Foundation/Foundation.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <signal.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/wait.h>
#import <unistd.h>

// The injection flow is a narrow Objective-C adaptation of the bundle discovery,
// backup and CoreTrust pipeline used by TrollFools (MIT, Lessica et al.).

extern char **environ;

static NSString * const OBGadgetFrameworkName = @"FridaGadget.framework";
static NSString * const OBGadgetExecutableName = @"FridaGadget";
static NSString * const OBGadgetPayloadName = @"FridaGadgetCore.dylib";
static NSString * const OBGadgetLoadPath = @"@executable_path/Frameworks/FridaGadget.framework/FridaGadget";
static NSString * const OBBackupSuffix = @".openbachelor-gadget.bak";
static NSString * const OBPreviousFrameworkSuffix = @".openbachelor.previous";
static NSString * const OBStagingFrameworkSuffix = @".openbachelor.staging";
static NSString * const OBSigningMarkerName = @".openbachelor-coretrust-v3";

static NSError *OBError(NSString *message) {
    return [NSError errorWithDomain:@"dev.openbachelor.injector" code:1
                            userInfo:@{NSLocalizedDescriptionKey: message ?: @"unknown error"}];
}

static uint32_t OBSwap32(uint32_t value) { return __builtin_bswap32(value); }
static uint64_t OBSwap64(uint64_t value) { return __builtin_bswap64(value); }

static BOOL OBReadExactly(int fd, void *buffer, size_t length, uint64_t offset) {
    uint8_t *cursor = buffer;
    size_t remaining = length;
    while (remaining != 0) {
        ssize_t count = pread(fd, cursor, remaining, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        cursor += count;
        remaining -= (size_t)count;
        offset += (uint64_t)count;
    }
    return YES;
}

static BOOL OBParseMachOSlice(const uint8_t *bytes, size_t length,
                              NSMutableSet<NSString *> *loads,
                              NSMutableSet<NSString *> *weakLoads,
                              NSMutableSet<NSString *> *strongLoads,
                              BOOL *protectedImage, BOOL *hasCodeSignature) {
    if (length < sizeof(struct mach_header_64)) return NO;
    const struct mach_header_64 *header = (const struct mach_header_64 *)bytes;
    if (header->magic != MH_MAGIC_64) return NO;
    size_t offset = sizeof(struct mach_header_64);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (offset > length || length - offset < sizeof(struct load_command)) return NO;
        const struct load_command *command = (const struct load_command *)(bytes + offset);
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > length - offset)
            return NO;
        if (command->cmd == LC_CODE_SIGNATURE) {
            *hasCodeSignature = YES;
        } else if (command->cmd == LC_ENCRYPTION_INFO && command->cmdsize >= sizeof(struct encryption_info_command)) {
            const struct encryption_info_command *encryption = (const struct encryption_info_command *)command;
            if (encryption->cryptid != 0) *protectedImage = YES;
        } else if (command->cmd == LC_ENCRYPTION_INFO_64 && command->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *encryption = (const struct encryption_info_command_64 *)command;
            if (encryption->cryptid != 0) *protectedImage = YES;
        } else if (command->cmd == LC_LOAD_DYLIB || command->cmd == LC_LOAD_WEAK_DYLIB ||
                   command->cmd == LC_REEXPORT_DYLIB || command->cmd == LC_LOAD_UPWARD_DYLIB) {
            if (command->cmdsize >= sizeof(struct dylib_command)) {
                const struct dylib_command *dylib = (const struct dylib_command *)command;
                uint32_t stringOffset = dylib->dylib.name.offset;
                if (stringOffset < command->cmdsize) {
                    const char *name = (const char *)command + stringOffset;
                    size_t maximum = command->cmdsize - stringOffset;
                    size_t nameLength = strnlen(name, maximum);
                    if (nameLength < maximum) {
                        NSString *value = [[NSString alloc] initWithBytes:name length:nameLength
                                                                  encoding:NSUTF8StringEncoding];
                        if (value.length != 0) {
                            [loads addObject:value];
                            if (command->cmd == LC_LOAD_WEAK_DYLIB) [weakLoads addObject:value];
                            else [strongLoads addObject:value];
                        }
                    }
                }
            }
        }
        offset += command->cmdsize;
    }
    return YES;
}

static BOOL OBParseMachOSliceAtOffset(int fd, uint64_t sliceOffset, uint64_t sliceSize,
                                      NSMutableSet<NSString *> *loads,
                                      NSMutableSet<NSString *> *weakLoads,
                                      NSMutableSet<NSString *> *strongLoads,
                                      BOOL *protectedImage, BOOL *hasCodeSignature) {
    if (sliceSize < sizeof(struct mach_header_64)) return NO;
    struct mach_header_64 header = {0};
    if (!OBReadExactly(fd, &header, sizeof(header), sliceOffset) || header.magic != MH_MAGIC_64)
        return NO;
    uint64_t headerLength = sizeof(header) + (uint64_t)header.sizeofcmds;
    // A normal iOS image uses only a few KiB of load commands. Keep malformed
    // input from turning this metadata-only parser into an unbounded allocator.
    if (headerLength > sliceSize || headerLength > 16 * 1024 * 1024) return NO;
    NSMutableData *headerData = [NSMutableData dataWithLength:(NSUInteger)headerLength];
    if (headerData == nil || !OBReadExactly(fd, headerData.mutableBytes,
                                             (size_t)headerLength, sliceOffset)) return NO;
    return OBParseMachOSlice(headerData.bytes, headerData.length, loads, weakLoads,
                             strongLoads, protectedImage, hasCodeSignature);
}

static NSDictionary *OBInspectMachO(NSString *path, NSError **error) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"无法读取 Mach-O：%@ (%s)", path, strerror(errno)]);
        return nil;
    }
    NSMutableSet<NSString *> *loads = [NSMutableSet set];
    NSMutableSet<NSString *> *weakLoads = [NSMutableSet set];
    NSMutableSet<NSString *> *strongLoads = [NSMutableSet set];
    struct stat attributes = {0};
    if (fstat(fd, &attributes) != 0 || attributes.st_size < (off_t)sizeof(uint32_t)) goto invalid;
    uint64_t length = (uint64_t)attributes.st_size;
    uint32_t magic = 0;
    if (!OBReadExactly(fd, &magic, sizeof(magic), 0)) goto invalid;
    BOOL protectedImage = NO;
    BOOL hasCodeSignature = NO;
    BOOL parsed = NO;
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        struct fat_header header = {0};
        if (length < sizeof(header) || !OBReadExactly(fd, &header, sizeof(header), 0)) goto invalid;
        BOOL swap = magic == FAT_CIGAM;
        uint32_t count = swap ? OBSwap32(header.nfat_arch) : header.nfat_arch;
        size_t archesLength = (size_t)count * sizeof(struct fat_arch);
        if (count > 64 || sizeof(header) + archesLength > length) goto invalid;
        struct fat_arch arches[64] = {0};
        if (!OBReadExactly(fd, arches, archesLength, sizeof(header))) goto invalid;
        for (uint32_t index = 0; index < count; index++) {
            uint32_t sliceOffset = swap ? OBSwap32(arches[index].offset) : arches[index].offset;
            uint32_t sliceSize = swap ? OBSwap32(arches[index].size) : arches[index].size;
            if (sliceOffset > length || sliceSize > length - sliceOffset ||
                !OBParseMachOSliceAtOffset(fd, sliceOffset, sliceSize, loads, weakLoads,
                                           strongLoads, &protectedImage,
                                           &hasCodeSignature)) goto invalid;
            parsed = YES;
        }
    } else if (magic == FAT_CIGAM_64 || magic == FAT_MAGIC_64) {
        struct fat_header header = {0};
        if (length < sizeof(header) || !OBReadExactly(fd, &header, sizeof(header), 0)) goto invalid;
        BOOL swap = magic == FAT_CIGAM_64;
        uint32_t count = swap ? OBSwap32(header.nfat_arch) : header.nfat_arch;
        size_t archesLength = (size_t)count * sizeof(struct fat_arch_64);
        if (count > 64 || sizeof(header) + archesLength > length) goto invalid;
        struct fat_arch_64 arches[64] = {0};
        if (!OBReadExactly(fd, arches, archesLength, sizeof(header))) goto invalid;
        for (uint32_t index = 0; index < count; index++) {
            uint64_t sliceOffset = swap ? OBSwap64(arches[index].offset) : arches[index].offset;
            uint64_t sliceSize = swap ? OBSwap64(arches[index].size) : arches[index].size;
            if (sliceOffset > length || sliceSize > length - sliceOffset ||
                !OBParseMachOSliceAtOffset(fd, sliceOffset, sliceSize, loads, weakLoads,
                                           strongLoads, &protectedImage,
                                           &hasCodeSignature)) goto invalid;
            parsed = YES;
        }
    } else {
        parsed = OBParseMachOSliceAtOffset(fd, 0, length, loads, weakLoads, strongLoads,
                                           &protectedImage, &hasCodeSignature);
    }
    if (!parsed) goto invalid;
    close(fd);
    return @{ @"loads": loads, @"weak_loads": weakLoads, @"strong_loads": strongLoads,
              @"protected": @(protectedImage), @"signed": @(hasCodeSignature),
              @"size": @(length) };

invalid:
    close(fd);
    if (error != NULL) *error = OBError([NSString stringWithFormat:@"Mach-O 结构无效或不受支持：%@", path]);
    return nil;
}

static BOOL OBLoadsGadget(NSDictionary *image) {
    NSSet<NSString *> *loads = image[@"loads"];
    for (NSString *load in loads) {
        if ([load hasSuffix:@"/FridaGadget.framework/FridaGadget"]) return YES;
    }
    return NO;
}

static BOOL OBLoadSetContainsGadget(NSSet<NSString *> *loads) {
    for (NSString *load in loads) {
        if ([load hasSuffix:@"/FridaGadget.framework/FridaGadget"]) return YES;
    }
    return NO;
}

static BOOL OBLoadsGadgetWeakly(NSDictionary *image) {
    return OBLoadSetContainsGadget(image[@"weak_loads"]) &&
           !OBLoadSetContainsGadget(image[@"strong_loads"]);
}

static BOOL OBIsHighRiskInjectionTarget(NSDictionary *image) {
    // UnityFramework is both the largest and most commonly integrity-checked
    // image in Unity games. Gadget only needs an image that dyld actually
    // loads; modifying UnityFramework itself is unnecessary and has caused
    // otherwise valid CoreTrust injections to be terminated at startup.
    return [[image[@"path"] lastPathComponent] isEqualToString:@"UnityFramework"];
}

static NSDictionary *OBTargetContext(NSString *bundleID, NSError **error) {
    NSFileManager *files = NSFileManager.defaultManager;
    NSString *applicationRoot = @"/var/containers/Bundle/Application";
    NSString *resolvedRoot = applicationRoot.stringByResolvingSymlinksInPath.stringByStandardizingPath;
    NSError *directoryError = nil;
    NSArray<NSString *> *containers = [files contentsOfDirectoryAtPath:applicationRoot error:&directoryError];
    if (containers == nil) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"无法读取 App Bundle 目录：%@",
                                              directoryError.localizedDescription ?: @"unknown error"]);
        return nil;
    }
    NSMutableArray<NSDictionary *> *matches = [NSMutableArray array];
    for (NSString *container in [containers sortedArrayUsingSelector:@selector(localizedStandardCompare:)]) {
        if ([container hasPrefix:@"."]) continue;
        NSString *containerPath = [applicationRoot stringByAppendingPathComponent:container];
        NSArray<NSString *> *items = [files contentsOfDirectoryAtPath:containerPath error:nil] ?: @[];
        for (NSString *item in items) {
            if (![item.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
            NSString *candidate = [containerPath stringByAppendingPathComponent:item];
            NSString *bundlePath = candidate.stringByResolvingSymlinksInPath.stringByStandardizingPath;
            NSString *allowedPrefix = [resolvedRoot stringByAppendingString:@"/"];
            if (![bundlePath hasPrefix:allowedPrefix]) continue;
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                                  [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *resolvedID = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
                ? info[@"CFBundleIdentifier"] : nil;
            if (![resolvedID isEqualToString:bundleID]) continue;
            [matches addObject:@{ @"bundle_path": bundlePath, @"info": info }];
        }
    }
    if (matches.count == 0) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"未安装目标应用：%@", bundleID]);
        return nil;
    }
    if (matches.count != 1) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"发现多个 Bundle ID 相同的目标，拒绝修改：%@", bundleID]);
        return nil;
    }
    NSString *bundlePath = matches.firstObject[@"bundle_path"];
    NSDictionary *info = matches.firstObject[@"info"];
    NSString *executableName = [info[@"CFBundleExecutable"] isKindOfClass:NSString.class] ? info[@"CFBundleExecutable"] : nil;
    if (executableName.length == 0) {
        if (error != NULL) *error = OBError(@"目标应用 Info.plist 缺少 CFBundleExecutable。");
        return nil;
    }
    NSString *executablePath = [bundlePath stringByAppendingPathComponent:executableName];
    if (![files fileExistsAtPath:executablePath]) {
        if (error != NULL) *error = OBError(@"目标应用主程序不存在。");
        return nil;
    }
    return @{
        @"bundle_id": bundleID,
        @"bundle_path": bundlePath,
        @"executable_path": executablePath,
        @"frameworks_path": [bundlePath stringByAppendingPathComponent:@"Frameworks"],
        @"version": [info[@"CFBundleShortVersionString"] description] ?: @"unknown",
        @"build": [info[@"CFBundleVersion"] description] ?: @"unknown",
    };
}

static NSArray<NSDictionary *> *OBCandidateImages(NSDictionary *context, NSError **error) {
    NSString *frameworksPath = context[@"frameworks_path"];
    NSArray<NSString *> *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:frameworksPath error:nil] ?: @[];
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    for (NSString *item in items) {
        if ([item hasPrefix:@"."] || [item isEqualToString:OBGadgetFrameworkName] || [item hasSuffix:OBBackupSuffix]) continue;
        NSString *itemPath = [frameworksPath stringByAppendingPathComponent:item];
        NSString *candidatePath = nil;
        if ([item.pathExtension.lowercaseString isEqualToString:@"framework"]) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[itemPath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *executable = [info[@"CFBundleExecutable"] isKindOfClass:NSString.class] ? info[@"CFBundleExecutable"] : nil;
            if (executable.length != 0) candidatePath = [itemPath stringByAppendingPathComponent:executable];
        } else if ([item.pathExtension.lowercaseString isEqualToString:@"dylib"]) {
            candidatePath = itemPath;
        }
        if (candidatePath.length == 0 || ![[NSFileManager defaultManager] fileExistsAtPath:candidatePath]) continue;
        NSError *inspectError = nil;
        NSDictionary *image = OBInspectMachO(candidatePath, &inspectError);
        if (image == nil) continue;
        NSMutableDictionary *record = [image mutableCopy];
        record[@"path"] = candidatePath.stringByStandardizingPath;
        [records addObject:record];
    }
    [records sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
        return [left[@"path"] localizedStandardCompare:right[@"path"]];
    }];
    if (records.count == 0 && error != NULL)
        *error = OBError(@"目标 App 没有可检查的 embedded framework/dylib；不能安全修改加密主程序。");
    return records;
}

static NSString *OBResolveLoad(NSString *load, NSString *loaderPath, NSDictionary *context) {
    NSString *resolved = nil;
    if ([load hasPrefix:@"@rpath/"]) {
        resolved = [context[@"frameworks_path"] stringByAppendingPathComponent:[load substringFromIndex:7]];
    } else if ([load hasPrefix:@"@executable_path/"]) {
        resolved = [context[@"bundle_path"] stringByAppendingPathComponent:[load substringFromIndex:17]];
    } else if ([load hasPrefix:@"@loader_path/"]) {
        resolved = [[loaderPath stringByDeletingLastPathComponent] stringByAppendingPathComponent:[load substringFromIndex:13]];
    }
    return resolved.stringByStandardizingPath;
}

static NSArray<NSDictionary *> *OBRankedCandidates(NSDictionary *context,
                                                    NSArray<NSDictionary *> *candidates,
                                                    NSError **error) {
    NSDictionary *mainImage = OBInspectMachO(context[@"executable_path"], error);
    if (mainImage == nil) return @[];
    NSMutableDictionary<NSString *, NSDictionary *> *byPath = [NSMutableDictionary dictionary];
    for (NSDictionary *candidate in candidates) byPath[candidate[@"path"]] = candidate;
    NSMutableSet<NSString *> *linked = [NSMutableSet set];
    NSMutableSet<NSString *> *visited = [NSMutableSet set];
    NSMutableArray<NSDictionary *> *queue = [NSMutableArray arrayWithObject:@{
        @"path": context[@"executable_path"], @"loads": mainImage[@"loads"]
    }];
    while (queue.count != 0) {
        NSDictionary *current = queue.firstObject;
        [queue removeObjectAtIndex:0];
        NSString *currentPath = current[@"path"];
        if ([visited containsObject:currentPath]) continue;
        [visited addObject:currentPath];
        for (NSString *load in current[@"loads"]) {
            NSString *resolved = OBResolveLoad(load, currentPath, context);
            NSDictionary *candidate = resolved != nil ? byPath[resolved] : nil;
            if (candidate != nil && ![linked containsObject:resolved]) {
                [linked addObject:resolved];
                [queue addObject:candidate];
            }
        }
    }
    NSMutableArray<NSDictionary *> *eligible = [NSMutableArray array];
    for (NSDictionary *candidate in candidates) {
        NSString *name = [candidate[@"path"] lastPathComponent].lowercaseString;
        if ([candidate[@"protected"] boolValue] || [name hasPrefix:@"libswift"] || OBLoadsGadget(candidate)) continue;
        NSMutableDictionary *ranked = [candidate mutableCopy];
        ranked[@"linked"] = @([linked containsObject:candidate[@"path"]]);
        [eligible addObject:ranked];
    }
    [eligible sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
        BOOL leftLinked = [left[@"linked"] boolValue];
        BOOL rightLinked = [right[@"linked"] boolValue];
        if (leftLinked != rightLinked) return leftLinked ? NSOrderedAscending : NSOrderedDescending;
        BOOL leftHighRisk = OBIsHighRiskInjectionTarget(left);
        BOOL rightHighRisk = OBIsHighRiskInjectionTarget(right);
        if (leftHighRisk != rightHighRisk)
            return leftHighRisk ? NSOrderedDescending : NSOrderedAscending;
        unsigned long long leftSize = [left[@"size"] unsignedLongLongValue];
        unsigned long long rightSize = [right[@"size"] unsignedLongLongValue];
        if (leftSize != rightSize) return leftSize < rightSize ? NSOrderedAscending : NSOrderedDescending;
        return [left[@"path"] localizedStandardCompare:right[@"path"]];
    }];
    return eligible;
}

static NSArray<NSDictionary *> *OBPatchedImages(NSDictionary *context, NSArray<NSDictionary *> *candidates) {
    NSMutableArray<NSDictionary *> *all = [candidates mutableCopy];
    NSDictionary *mainImage = OBInspectMachO(context[@"executable_path"], nil);
    if (mainImage != nil) {
        NSMutableDictionary *mainRecord = [mainImage mutableCopy];
        mainRecord[@"path"] = context[@"executable_path"];
        [all addObject:mainRecord];
    }
    NSPredicate *predicate = [NSPredicate predicateWithBlock:^BOOL(NSDictionary *record, NSDictionary *bindings) {
        (void)bindings;
        return OBLoadsGadget(record);
    }];
    return [all filteredArrayUsingPredicate:predicate];
}

static BOOL OBRunTool(NSString *appRoot, NSString *name, NSArray<NSString *> *arguments,
                      NSString **capturedOutput, NSError **error) {
    NSString *toolPath = [[appRoot stringByAppendingPathComponent:@"InjectorTools"] stringByAppendingPathComponent:name];
    if (access(toolPath.fileSystemRepresentation, X_OK) != 0) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"缺少设备端工具：%@", name]);
        return NO;
    }
    int outputPipe[2] = {-1, -1};
    if (pipe(outputPipe) != 0) {
        if (error != NULL) *error = OBError(@"无法创建工具输出管道。");
        return NO;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, outputPipe[0]);
    posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, outputPipe[1]);
    size_t count = arguments.count + 2;
    char **argv = calloc(count, sizeof(char *));
    argv[0] = strdup(toolPath.fileSystemRepresentation);
    for (NSUInteger index = 0; index < arguments.count; index++)
        argv[index + 1] = strdup(arguments[index].UTF8String);
    setenv("DISABLE_TWEAKS", "1", 1);
    pid_t pid = 0;
    int spawnResult = posix_spawn(&pid, toolPath.fileSystemRepresentation, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger index = 0; index < count - 1; index++) free(argv[index]);
    free(argv);
    close(outputPipe[1]);
    NSMutableData *output = [NSMutableData data];
    uint8_t buffer[4096];
    ssize_t bytesRead = 0;
    while ((bytesRead = read(outputPipe[0], buffer, sizeof(buffer))) > 0) {
        if (output.length < 1024 * 1024) [output appendBytes:buffer length:(NSUInteger)bytesRead];
    }
    close(outputPipe[0]);
    int status = 0;
    while (spawnResult == 0 && waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    NSString *outputText = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] ?: @"";
    if (capturedOutput != NULL) *capturedOutput = outputText;
    BOOL succeeded = spawnResult == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!succeeded && error != NULL) {
        NSString *bounded = outputText.length > 800 ? [outputText substringToIndex:800] : outputText;
        *error = OBError([NSString stringWithFormat:@"%@ 执行失败（spawn=%d, status=%d）：%@",
                          name, spawnResult, status, bounded]);
    }
    return succeeded;
}

static NSString *OBTeamIDForExecutable(NSString *executablePath, NSString *appRoot,
                                       NSError **error) {
    NSString *output = nil;
    NSError *toolError = nil;
    if (!OBRunTool(appRoot, @"ldid", @[@"-e", executablePath], &output, &toolError)) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"无法读取目标签名 Team ID：%@",
                                              toolError.localizedDescription ?: @"unknown error"]);
        return nil;
    }
    NSRange start = [output rangeOfString:@"<plist"];
    NSRange end = [output rangeOfString:@"</plist>" options:NSBackwardsSearch];
    if (start.location == NSNotFound || end.location == NSNotFound || end.location < start.location) {
        if (error != NULL) *error = OBError(@"目标主程序没有可解析的签名 entitlements，拒绝使用虚构 Team ID。");
        return nil;
    }
    NSRange plistRange = NSMakeRange(start.location, NSMaxRange(end) - start.location);
    NSData *plistData = [[output substringWithRange:plistRange] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *entitlements = [NSPropertyListSerialization propertyListWithData:plistData
        options:NSPropertyListImmutable format:nil error:nil];
    if (![entitlements isKindOfClass:NSDictionary.class]) {
        if (error != NULL) *error = OBError(@"目标主程序签名 entitlements 格式无效。");
        return nil;
    }
    NSString *teamID = [entitlements[@"com.apple.developer.team-identifier"] isKindOfClass:NSString.class]
        ? entitlements[@"com.apple.developer.team-identifier"] : nil;
    if (teamID.length == 0) {
        NSString *applicationID = [entitlements[@"application-identifier"] isKindOfClass:NSString.class]
            ? entitlements[@"application-identifier"] : nil;
        NSRange separator = [applicationID rangeOfString:@"."];
        if (separator.location != NSNotFound && separator.location != 0)
            teamID = [applicationID substringToIndex:separator.location];
    }
    if (teamID.length == 0) {
        if (error != NULL) *error = OBError(@"无法从目标主程序签名中确定 Team ID，已取消注入。");
        return nil;
    }
    return teamID;
}

static BOOL OBCopyReplacing(NSString *source, NSString *destination, NSError **error) {
    NSFileManager *files = NSFileManager.defaultManager;
    [files removeItemAtPath:destination error:nil];
    if (![files createDirectoryAtPath:destination.stringByDeletingLastPathComponent
          withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    return [files copyItemAtPath:source toPath:destination error:error];
}

static BOOL OBRemove(NSString *path, NSError **error) {
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return YES;
    return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
}

static BOOL OBChownRecursively(NSString *path, uid_t uid, gid_t gid, NSError **error) {
    if (lchown(path.fileSystemRepresentation, uid, gid) != 0) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"chown 失败：%@ (%s)", path, strerror(errno)]);
        return NO;
    }
    NSDirectoryEnumerator<NSURL *> *enumerator = [[NSFileManager defaultManager]
        enumeratorAtURL:[NSURL fileURLWithPath:path] includingPropertiesForKeys:nil options:0 errorHandler:nil];
    for (NSURL *url in enumerator) {
        if (lchown(url.fileSystemRepresentation, uid, gid) != 0) {
            if (error != NULL) *error = OBError([NSString stringWithFormat:@"chown 失败：%@ (%s)", url.path, strerror(errno)]);
            return NO;
        }
    }
    return YES;
}

static BOOL OBAtomicRestore(NSString *backup, NSString *target, NSError **error) {
    NSString *temporary = [target stringByAppendingString:@".openbachelor.restore"];
    if (!OBCopyReplacing(backup, temporary, error)) return NO;
    if (!OBChownRecursively(temporary, 33, 33, error)) {
        OBRemove(temporary, nil);
        return NO;
    }
    if (rename(temporary.fileSystemRepresentation, target.fileSystemRepresentation) != 0) {
        if (error != NULL) *error = OBError([NSString stringWithFormat:@"原子恢复失败：%s", strerror(errno)]);
        OBRemove(temporary, nil);
        return NO;
    }
    return YES;
}

static BOOL OBSignForCoreTrust(NSString *path, NSString *teamID, NSString *appRoot, NSError **error) {
    // Match TrollFools' cmdCoreTrustBypass exactly: insert_dylib preserves the
    // existing LC_CODE_SIGNATURE, and ct_bypass must transform that signature
    // directly. Replacing it unconditionally with ldid produces an Invalid
    // Page kill in dyld on iOS 16.2. Only unsigned inputs need pseudo-signing.
    NSDictionary *image = OBInspectMachO(path, error);
    if (image == nil) return NO;
    if (![image[@"signed"] boolValue] &&
        !OBRunTool(appRoot, @"ldid", @[@"-S", path], nil, error)) return NO;
    return OBRunTool(appRoot, @"ct_bypass", @[@"-r", @"-i", path, @"-t", teamID], nil, error);
}

static NSArray<NSNumber *> *OBPIDsForExecutable(NSString *executablePath) {
    size_t processLength = 0;
    int query[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    if (sysctl(query, 3, NULL, &processLength, NULL, 0) < 0 || processLength == 0) return @[];
    struct kinfo_proc *processes = calloc(1, processLength);
    if (processes == NULL) return @[];
    if (sysctl(query, 3, processes, &processLength, NULL, 0) < 0) {
        free(processes);
        return @[];
    }
    int maximumArguments = 4096;
    size_t maximumLength = sizeof(maximumArguments);
    sysctl((int[]){CTL_KERN, KERN_ARGMAX}, 2, &maximumArguments, &maximumLength, NULL, 0);
    NSMutableArray<NSNumber *> *result = [NSMutableArray array];
    NSUInteger count = processLength / sizeof(struct kinfo_proc);
    for (NSUInteger index = 0; index < count; index++) {
        pid_t pid = processes[index].kp_proc.p_pid;
        if (pid <= 1 || pid == getpid()) continue;
        size_t argumentLength = (size_t)maximumArguments;
        char *arguments = calloc(1, argumentLength + 1);
        if (arguments == NULL) continue;
        int argumentQuery[] = {CTL_KERN, KERN_PROCARGS2, pid, 0};
        if (sysctl(argumentQuery, 3, arguments, &argumentLength, NULL, 0) == 0) {
            NSString *path = [NSString stringWithUTF8String:arguments + sizeof(int)];
            if ([path isEqualToString:executablePath]) [result addObject:@(pid)];
        }
        free(arguments);
    }
    free(processes);
    return result;
}

static BOOL OBTerminateTarget(NSString *executablePath, NSError **error) {
    NSArray<NSNumber *> *pids = OBPIDsForExecutable(executablePath);
    for (NSNumber *value in pids) kill(value.intValue, SIGTERM);
    for (NSUInteger attempt = 0; attempt < 40; attempt++) {
        BOOL running = NO;
        for (NSNumber *value in pids) if (kill(value.intValue, 0) == 0) running = YES;
        if (!running) return YES;
        usleep(50000);
    }
    for (NSNumber *value in pids) if (kill(value.intValue, 0) == 0) kill(value.intValue, SIGKILL);
    usleep(100000);
    for (NSNumber *value in pids) {
        if (kill(value.intValue, 0) == 0) {
            if (error != NULL) *error = OBError(@"目标 App 未能退出；为避免损坏，本次注入已取消。");
            return NO;
        }
    }
    return YES;
}

static NSDictionary *OBInspection(NSDictionary *context, NSArray<NSDictionary *> *candidates) {
    NSArray<NSDictionary *> *patched = OBPatchedImages(context, candidates);
    NSString *frameworkPath = [context[@"frameworks_path"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    NSString *frameworkBinary = [frameworkPath stringByAppendingPathComponent:OBGadgetExecutableName];
    BOOL frameworkPresent = [[NSFileManager defaultManager] fileExistsAtPath:frameworkBinary];
    BOOL owned = NO;
    for (NSDictionary *record in patched) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:[record[@"path"] stringByAppendingString:OBBackupSuffix]]) {
            owned = YES;
            break;
        }
    }
    NSString *state = @"absent";
    NSString *message = @"尚未注入 Gadget；启动时会自动安装。";
    if (patched.count != 0 && frameworkPresent) {
        state = owned ? @"installed" : @"external";
        message = owned ? @"Gadget 已由 Launcher 安装，可直接启动。" : @"检测到外部工具注入的 Gadget；可直接启动，但应由原工具移除。";
    } else if (patched.count != 0) {
        state = @"repair";
        message = @"检测到 Gadget load command，但 framework 缺失；需要修复。";
    } else if (frameworkPresent) {
        state = @"stale";
        message = @"发现未被加载的残留 Gadget framework；安装时会替换。";
    }
    NSMutableDictionary *result = [@{
        @"ok": @YES, @"state": state, @"message": message,
        @"bundle_id": context[@"bundle_id"], @"version": context[@"version"],
        @"build": context[@"build"], @"framework_present": @(frameworkPresent),
        @"load_present": @(patched.count != 0), @"owned": @(owned),
    } mutableCopy];
    if (patched.count != 0) result[@"target_path"] = patched.firstObject[@"path"];
    return result;
}

static BOOL OBPrepareFramework(NSDictionary *context, NSString *appRoot,
                               BOOL *swapped, BOOL *hadPrevious, NSError **error) {
    NSString *frameworksPath = context[@"frameworks_path"];
    NSString *source = [[appRoot stringByAppendingPathComponent:@"InjectorResources"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    NSString *sourcePayload = [source stringByAppendingPathComponent:OBGadgetPayloadName];
    NSString *final = [frameworksPath stringByAppendingPathComponent:OBGadgetFrameworkName];
    NSString *staging = [final stringByAppendingString:OBStagingFrameworkSuffix];
    NSString *previous = [final stringByAppendingString:OBPreviousFrameworkSuffix];
    NSFileManager *files = NSFileManager.defaultManager;
    if (![files fileExistsAtPath:[source stringByAppendingPathComponent:OBGadgetExecutableName]] ||
        ![files fileExistsAtPath:sourcePayload]) {
        if (error != NULL) *error = OBError(@"launcher 内置 Gadget 资源不完整。");
        return NO;
    }
    if (![files createDirectoryAtPath:frameworksPath withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if ([files fileExistsAtPath:previous]) {
        if (![files fileExistsAtPath:final]) {
            if (rename(previous.fileSystemRepresentation, final.fileSystemRepresentation) != 0) {
                if (error != NULL) *error = OBError(@"无法恢复上次中断的 Gadget framework。");
                return NO;
            }
        } else {
            [files removeItemAtPath:previous error:nil];
        }
    }
    [files removeItemAtPath:staging error:nil];
    if (!OBCopyReplacing(source, staging, error)) return NO;
    // Preserve TrollFools ownership metadata when repairing an externally
    // injected framework so its original eject flow can still recognize it.
    if ([files fileExistsAtPath:[final stringByAppendingPathComponent:@".troll-fools"]]) {
        [[NSData data] writeToFile:[staging stringByAppendingPathComponent:@".troll-fools"]
                           options:NSDataWritingAtomic error:nil];
    }
    NSString *stagingBinary = [staging stringByAppendingPathComponent:OBGadgetExecutableName];
    NSString *stagingPayload = [staging stringByAppendingPathComponent:OBGadgetPayloadName];
    if (!OBSignForCoreTrust(stagingBinary, context[@"team_id"], appRoot, error) ||
        !OBSignForCoreTrust(stagingPayload, context[@"team_id"], appRoot, error) ||
        !OBChownRecursively(staging, 33, 33, error)) {
        [files removeItemAtPath:staging error:nil];
        return NO;
    }
    *hadPrevious = [files fileExistsAtPath:final];
    if (*hadPrevious && rename(final.fileSystemRepresentation, previous.fileSystemRepresentation) != 0) {
        if (error != NULL) *error = OBError(@"无法备份现有 Gadget framework。");
        [files removeItemAtPath:staging error:nil];
        return NO;
    }
    if (rename(staging.fileSystemRepresentation, final.fileSystemRepresentation) != 0) {
        if (*hadPrevious) rename(previous.fileSystemRepresentation, final.fileSystemRepresentation);
        if (error != NULL) *error = OBError(@"无法启用已签名的 Gadget framework。");
        return NO;
    }
    *swapped = YES;
    return YES;
}

static void OBRollbackFramework(NSDictionary *context, BOOL swapped, BOOL hadPrevious) {
    if (!swapped) return;
    NSString *final = [context[@"frameworks_path"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    NSString *previous = [final stringByAppendingString:OBPreviousFrameworkSuffix];
    OBRemove(final, nil);
    if (hadPrevious) rename(previous.fileSystemRepresentation, final.fileSystemRepresentation);
}

static void OBCommitFramework(NSDictionary *context) {
    NSString *final = [context[@"frameworks_path"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    OBRemove([final stringByAppendingString:OBPreviousFrameworkSuffix], nil);
}

static BOOL OBMigrateLegacyOwnedInjections(NSArray<NSDictionary *> *patched,
                                           BOOL forceOwnedMigration,
                                           BOOL *migrated, NSError **error) {
    NSFileManager *files = NSFileManager.defaultManager;
    for (NSDictionary *record in patched) {
        NSString *target = record[@"path"];
        NSString *backup = [target stringByAppendingString:OBBackupSuffix];
        BOOL owned = [files fileExistsAtPath:backup];
        BOOL legacy = forceOwnedMigration || !OBLoadsGadgetWeakly(record) ||
                      OBIsHighRiskInjectionTarget(record);
        if (!owned || !legacy) continue;

        if (!OBAtomicRestore(backup, target, error)) return NO;
        NSDictionary *restored = OBInspectMachO(target, error);
        if (restored == nil || OBLoadsGadget(restored)) {
            if (error != NULL && *error == nil)
                *error = OBError(@"旧版注入恢复后仍包含 Gadget load command，已停止迁移。");
            return NO;
        }
        if (!OBRemove(backup, error)) return NO;
        *migrated = YES;
    }
    return YES;
}

static NSDictionary *OBInstall(NSDictionary *context, NSString *appRoot, NSError **error) {
    NSString *teamID = OBTeamIDForExecutable(context[@"executable_path"], appRoot, error);
    if (teamID == nil) return nil;
    NSMutableDictionary *signingContext = [context mutableCopy];
    signingContext[@"team_id"] = teamID;
    context = signingContext;
    NSArray<NSDictionary *> *candidates = OBCandidateImages(context, error);
    if (candidates.count == 0) return nil;
    if (!OBTerminateTarget(context[@"executable_path"], error)) return nil;
    NSArray<NSDictionary *> *patched = OBPatchedImages(context, candidates);
    NSString *installedFramework = [context[@"frameworks_path"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    BOOL currentSigningPipeline = [[NSFileManager defaultManager]
        fileExistsAtPath:[installedFramework stringByAppendingPathComponent:OBSigningMarkerName]];
    BOOL migratedLegacyInjection = NO;
    if (!OBMigrateLegacyOwnedInjections(patched, !currentSigningPipeline,
                                        &migratedLegacyInjection, error))
        return nil;
    if (migratedLegacyInjection) {
        candidates = OBCandidateImages(context, error);
        if (candidates.count == 0) return nil;
        patched = OBPatchedImages(context, candidates);
    }
    BOOL frameworkSwapped = NO;
    BOOL frameworkHadPrevious = NO;
    if (!OBPrepareFramework(context, appRoot, &frameworkSwapped, &frameworkHadPrevious, error)) return nil;
    if (patched.count == 0) {
        NSArray<NSDictionary *> *ranked = OBRankedCandidates(context, candidates, error);
        if (ranked.count == 0) {
            OBRollbackFramework(context, frameworkSwapped, frameworkHadPrevious);
            if (error != NULL && *error == nil)
                *error = OBError(@"没有可安全修改的未加密 framework；请改用已解密 IPA。");
            return nil;
        }
        NSString *target = ranked.firstObject[@"path"];
        NSString *backup = [target stringByAppendingString:OBBackupSuffix];
        NSFileManager *files = NSFileManager.defaultManager;
        BOOL backupExists = [files fileExistsAtPath:backup];
        if (backupExists && ![files contentsEqualAtPath:target andPath:backup]) {
            // A target update or an interrupted external modification can leave
            // a stale backup at the same bundle path. Never restore across builds.
            if (!OBRemove(backup, error)) {
                OBRollbackFramework(context, frameworkSwapped, frameworkHadPrevious);
                return nil;
            }
            backupExists = NO;
        }
        BOOL createdBackup = !backupExists;
        if (createdBackup && (!OBCopyReplacing(target, backup, error) || !OBChownRecursively(backup, 33, 33, error))) {
            OBRollbackFramework(context, frameworkSwapped, frameworkHadPrevious);
            return nil;
        }
        NSDictionary *backupImage = OBInspectMachO(backup, error);
        if (backupImage == nil || OBLoadsGadget(backupImage)) {
            if (error != NULL && *error == nil) *error = OBError(@"注入备份无效，拒绝继续修改。");
            OBRollbackFramework(context, frameworkSwapped, frameworkHadPrevious);
            return nil;
        }
        BOOL patchedTarget = OBRunTool(appRoot, @"insert_dylib",
            @[OBGadgetLoadPath, target, @"--inplace", @"--overwrite", @"--no-strip-codesig",
              @"--all-yes", @"--weak"], nil, error);
        NSDictionary *patchedImage = patchedTarget ? OBInspectMachO(target, error) : nil;
        if (patchedImage == nil || !OBLoadsGadgetWeakly(patchedImage) ||
            !OBSignForCoreTrust(target, context[@"team_id"], appRoot, error) ||
            !OBChownRecursively(target, 33, 33, error)) {
            NSError *injectionError = error != NULL ? *error : nil;
            NSError *restoreError = nil;
            BOOL restored = OBAtomicRestore(backup, target, &restoreError);
            if (restored && createdBackup) OBRemove(backup, nil);
            OBRollbackFramework(context, frameworkSwapped, frameworkHadPrevious);
            if (error != NULL) {
                if (!restored) {
                    *error = OBError([NSString stringWithFormat:@"注入失败且自动恢复失败：%@；恢复错误：%@",
                                      injectionError.localizedDescription ?: @"unknown",
                                      restoreError.localizedDescription ?: @"unknown"]);
                } else if (*error == nil) {
                    *error = OBError(@"目标 Mach-O 注入失败，已恢复备份。");
                }
            }
            return nil;
        }
    }
    OBCommitFramework(context);
    NSArray<NSDictionary *> *updatedCandidates = OBCandidateImages(context, nil);
    NSDictionary *inspection = OBInspection(context, updatedCandidates);
    NSMutableDictionary *result = [inspection mutableCopy];
    if (migratedLegacyInjection) {
        result[@"message"] = @"已恢复旧版高风险注入，并改用小型已链接 framework 的弱依赖 Gadget；可重新启动。";
    } else {
        result[@"message"] = [inspection[@"state"] isEqualToString:@"external"]
            ? @"外部 Gadget load command 已保留，内置 framework 已修复并签名。"
            : @"Gadget 已原子安装并通过 CoreTrust 处理，可直接启动。";
    }
    return result;
}

static NSDictionary *OBRemoveInstallation(NSDictionary *context, NSError **error) {
    NSArray<NSDictionary *> *candidates = OBCandidateImages(context, nil);
    NSArray<NSDictionary *> *patched = OBPatchedImages(context, candidates);
    for (NSDictionary *record in patched) {
        NSString *backup = [record[@"path"] stringByAppendingString:OBBackupSuffix];
        if (![[NSFileManager defaultManager] fileExistsAtPath:backup]) {
            if (error != NULL) *error = OBError(@"Gadget 由外部工具注入且没有 Launcher 备份；请使用原注入工具移除。");
            return nil;
        }
    }
    if (!OBTerminateTarget(context[@"executable_path"], error)) return nil;
    for (NSDictionary *record in patched) {
        NSString *target = record[@"path"];
        NSString *backup = [target stringByAppendingString:OBBackupSuffix];
        if (!OBAtomicRestore(backup, target, error)) return nil;
        NSDictionary *restored = OBInspectMachO(target, error);
        if (restored == nil || OBLoadsGadget(restored)) {
            if (error != NULL && *error == nil) *error = OBError(@"恢复后的 Mach-O 仍包含 Gadget load command。");
            return nil;
        }
        OBRemove(backup, nil);
    }
    NSString *framework = [context[@"frameworks_path"] stringByAppendingPathComponent:OBGadgetFrameworkName];
    if (!OBRemove(framework, error)) return nil;
    OBRemove([framework stringByAppendingString:OBPreviousFrameworkSuffix], nil);
    OBRemove([framework stringByAppendingString:OBStagingFrameworkSuffix], nil);
    NSMutableDictionary *result = [OBInspection(context, OBCandidateImages(context, nil)) mutableCopy];
    result[@"message"] = @"Launcher 注入的 Gadget 已移除，原始 Mach-O 已恢复。";
    return result;
}

static void OBPrintJSON(NSDictionary *result) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    if (data != nil) fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        setvbuf(stderr, NULL, _IONBF, 0);
        fprintf(stderr, "injector-stage: started\n");
        if (argc != 3) {
            OBPrintJSON(@{ @"ok": @NO, @"state": @"error", @"error": @"usage: OpenBachelorInjector inspect|install|remove BUNDLE_ID" });
            return 2;
        }
        if (geteuid() != 0) {
            OBPrintJSON(@{ @"ok": @NO, @"state": @"error", @"error": @"root persona 未生效；请确认由 TrollStore 安装。" });
            return 1;
        }
        NSString *command = @(argv[1]);
        NSString *bundleID = @(argv[2]);
        NSString *appRoot = [@(argv[0]) stringByDeletingLastPathComponent].stringByStandardizingPath;
        NSError *error = nil;
        fprintf(stderr, "injector-stage: resolving-target\n");
        NSDictionary *context = OBTargetContext(bundleID, &error);
        NSDictionary *result = nil;
        if (context != nil) {
            fprintf(stderr, "injector-stage: target-resolved\n");
            if ([command isEqualToString:@"inspect"]) {
                fprintf(stderr, "injector-stage: inspecting-mach-o\n");
                NSArray *candidates = OBCandidateImages(context, nil);
                result = OBInspection(context, candidates);
            } else if ([command isEqualToString:@"install"]) {
                fprintf(stderr, "injector-stage: installing\n");
                result = OBInstall(context, appRoot, &error);
            } else if ([command isEqualToString:@"remove"]) {
                fprintf(stderr, "injector-stage: removing\n");
                result = OBRemoveInstallation(context, &error);
            } else {
                error = OBError(@"未知 injector 命令。");
            }
        }
        fprintf(stderr, "injector-stage: complete\n");
        if (result == nil) result = @{ @"ok": @NO, @"state": @"error", @"error": error.localizedDescription ?: @"unknown error" };
        OBPrintJSON(result);
        return [result[@"ok"] boolValue] ? 0 : 1;
    }
}
