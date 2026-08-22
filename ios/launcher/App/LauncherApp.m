#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <dispatch/dispatch.h>
#import <objc/message.h>
#import <errno.h>
#import <spawn.h>
#import <signal.h>
#import <string.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <unistd.h>

#define OBProcPathSize 4096
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

extern char **environ;
extern int posix_spawnattr_set_persona_np(posix_spawnattr_t *attr, uid_t persona_id, uint32_t flags);
extern int posix_spawnattr_set_persona_uid_np(posix_spawnattr_t *attr, uid_t uid);
extern int posix_spawnattr_set_persona_gid_np(posix_spawnattr_t *attr, uid_t gid);

static const uint32_t OBPersonaOverride = 1;

static NSString * const OBStateDirectory = @"/var/mobile/Library/OpenBachelorLauncher";
static NSString * const OBHelperPIDPath = @"/var/mobile/Library/OpenBachelorLauncher/helper.pid";
static NSString * const OBStatusPath = @"/var/mobile/Library/OpenBachelorLauncher/status.json";
// Keep the helper state outside the app container (it is also used by the
// root-persona helper), but put all user-facing logs in Documents.  With
// UIFileSharingEnabled enabled in Info.plist this directory is visible in the
// system Files app under "On My iPhone/OB Launcher/Logs".
static NSString *OBLogPath;
static NSString *OBLogsDirectory;

static void OBPrepareUserLogPaths(void) {
    if (OBLogsDirectory.length != 0 && OBLogPath.length != 0) return;
    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                               NSUserDomainMask, YES).firstObject;
    if (documents.length == 0) return;
    OBLogsDirectory = [documents stringByAppendingPathComponent:@"Logs"];
    OBLogPath = [OBLogsDirectory stringByAppendingPathComponent:@"session.log"];
}

static NSDictionary *OBRunInjector(NSString *command, NSString *bundleID, NSError **error) {
    NSString *injector = [NSBundle.mainBundle pathForResource:@"OpenBachelorInjector" ofType:nil];
    if (injector.length == 0) {
        if (error != NULL) *error = [NSError errorWithDomain:@"dev.openbachelor.launcher" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"IPA 缺少 OpenBachelorInjector。"}];
        return nil;
    }
    int outputPipe[2] = {-1, -1};
    if (pipe(outputPipe) != 0) {
        if (error != NULL) *error = [NSError errorWithDomain:@"dev.openbachelor.launcher" code:2
            userInfo:@{NSLocalizedDescriptionKey: @"无法创建 injector 输出管道。"}];
        return nil;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, outputPipe[0]);
    posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, outputPipe[1]);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    int personaResult = posix_spawnattr_set_persona_np(&attributes, 99, OBPersonaOverride);
    if (personaResult == 0) personaResult = posix_spawnattr_set_persona_uid_np(&attributes, 0);
    if (personaResult == 0) personaResult = posix_spawnattr_set_persona_gid_np(&attributes, 0);
    if (personaResult != 0) {
        posix_spawnattr_destroy(&attributes);
        posix_spawn_file_actions_destroy(&actions);
        close(outputPipe[0]);
        close(outputPipe[1]);
        if (error != NULL) *error = [NSError errorWithDomain:@"dev.openbachelor.launcher" code:3
            userInfo:@{NSLocalizedDescriptionKey: @"无法配置 root persona；请确认由 TrollStore 安装。"}];
        return nil;
    }
    char *argv[] = {(char *)injector.fileSystemRepresentation, (char *)command.UTF8String,
        (char *)bundleID.UTF8String, NULL};
    // Match TrollFools' root-spawn environment. On jailbroken devices this
    // prevents unrelated tweak loaders from entering the privileged helper.
    setenv("DISABLE_TWEAKS", "1", 1);
    pid_t pid = 0;
    int spawnResult = posix_spawn(&pid, injector.fileSystemRepresentation, &actions, &attributes, argv, environ);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
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
    id value = output.length != 0 ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil] : nil;
    if (![value isKindOfClass:NSDictionary.class] && output.length != 0) {
        NSString *text = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] ?: @"";
        for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet].reverseObjectEnumerator) {
            NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
            id candidate = lineData.length != 0 ? [NSJSONSerialization JSONObjectWithData:lineData options:0 error:nil] : nil;
            if ([candidate isKindOfClass:NSDictionary.class]) { value = candidate; break; }
        }
    }
    if ([value isKindOfClass:NSDictionary.class]) return value;
    if (error != NULL) {
        NSString *detail = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] ?: @"";
        NSString *termination = nil;
        if (spawnResult != 0) termination = [NSString stringWithFormat:@"spawn=%d", spawnResult];
        else if (WIFSIGNALED(status)) termination = [NSString stringWithFormat:@"signal=%d (%s)",
                                                       WTERMSIG(status), strsignal(WTERMSIG(status))];
        else if (WIFEXITED(status)) termination = [NSString stringWithFormat:@"exit=%d", WEXITSTATUS(status)];
        else termination = [NSString stringWithFormat:@"wait_status=%d", status];
        *error = [NSError errorWithDomain:@"dev.openbachelor.launcher" code:4 userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"injector 启动失败（%@）：%@",
                                         termination, detail]
        }];
    }
    return nil;
}

@interface OBLauncherViewController : UIViewController <UITextFieldDelegate, UIDocumentPickerDelegate>
@end

@implementation OBLauncherViewController {
    UITextField *_bundleField;
    UITextField *_endpointField;
    UISegmentedControl *_backendControl;
    UISegmentedControl *_modeControl;
    UISwitch *_sslSwitch;
    UISwitch *_signatureSwitch;
    UISwitch *_passthroughSwitch;
    UISwitch *_overlaySwitch;
    UISwitch *_logConsoleSwitch;
    UISwitch *_battleFinishBlockSwitch;
    UISwitch *_trainerSwitch;
    UILabel *_gadgetStatusLabel;
    UILabel *_statusLabel;
    UIButton *_launchButton;
    UIButton *_installGadgetButton;
    UIButton *_removeGadgetButton;
    NSTimer *_logTimer;
    NSString *_activeSessionID;
    BOOL _targetOpenedForSession;
    BOOL _injectorOperationRunning;
}

static UIColor *OBBackground(void) { return [UIColor colorWithRed:0.035 green:0.055 blue:0.071 alpha:1]; }
static UIColor *OBCard(void) { return [UIColor colorWithRed:0.075 green:0.102 blue:0.122 alpha:1]; }
static UIColor *OBAccent(void) { return [UIColor colorWithRed:0.20 green:0.89 blue:0.78 alpha:1]; }
static UIColor *OBSecondary(void) { return [UIColor colorWithWhite:0.72 alpha:1]; }

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = OBBackground();

    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;
    [self.view addSubview:scroll];

    UIStackView *content = [UIStackView new];
    content.axis = UILayoutConstraintAxisVertical;
    content.spacing = 18;
    content.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:content];
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [content.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:28],
        [content.leadingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.leadingAnchor constant:22],
        [content.trailingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.trailingAnchor constant:-22],
        [content.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-34],
    ]];

    UILabel *eyebrow = [self label:@"OPENBACHELOR / DEVICE CONTROL" size:12 weight:UIFontWeightSemibold color:OBAccent()];
    eyebrow.accessibilityTraits = UIAccessibilityTraitHeader;
    [content addArrangedSubview:eyebrow];
    UILabel *title = [self label:@"一键启动抓包链路" size:30 weight:UIFontWeightBold color:UIColor.whiteColor];
    title.numberOfLines = 0;
    [content addArrangedSubview:title];
    UILabel *subtitle = [self label:@"通过 TrollStore Gadget 或越狱 Frida，在设备本机启动目标应用并保持 direct agent 在线。" size:15 weight:UIFontWeightRegular color:OBSecondary()];
    subtitle.numberOfLines = 0;
    [content addArrangedSubview:subtitle];

    UIView *configCard = [self card];
    UIStackView *form = [self stackInCard:configCard];
    [content addArrangedSubview:configCard];
    [form addArrangedSubview:[self sectionLabel:@"启动配置"]];
    _backendControl = [[UISegmentedControl alloc] initWithItems:@[@"TrollStore Gadget", @"越狱 Frida"]];
    _backendControl.selectedSegmentIndex = 0;
    _backendControl.selectedSegmentTintColor = OBAccent();
    _backendControl.accessibilityLabel = @"注入后端";
    [_backendControl addTarget:self action:@selector(backendControlChanged) forControlEvents:UIControlEventValueChanged];
    [form addArrangedSubview:_backendControl];
    _modeControl = [[UISegmentedControl alloc] initWithItems:@[@"服务重定向", @"本机抓包"]];
    _modeControl.selectedSegmentIndex = 0;
    _modeControl.selectedSegmentTintColor = OBAccent();
    [_modeControl addTarget:self action:@selector(modeChanged) forControlEvents:UIControlEventValueChanged];
    _modeControl.accessibilityLabel = @"工作模式";
    [form addArrangedSubview:_modeControl];

    _bundleField = [self textField:@"目标 Bundle ID" placeholder:@"com.hypergryph.arknights"];
    _bundleField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    [_bundleField addTarget:self action:@selector(bundleEditingEnded) forControlEvents:UIControlEventEditingDidEnd];
    [form addArrangedSubview:_bundleField];
    _endpointField = [self textField:@"重定向服务 URL" placeholder:@"http://192.168.1.20:8443"];
    _endpointField.keyboardType = UIKeyboardTypeURL;
    _endpointField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    [form addArrangedSubview:_endpointField];
    UISwitch *sslSwitch;
    UISwitch *signatureSwitch;
    UISwitch *passthroughSwitch;
    UISwitch *overlaySwitch;
    UISwitch *logConsoleSwitch;
    UISwitch *battleFinishBlockSwitch;
    UISwitch *trainerSwitch;
    [form addArrangedSubview:[self switchRow:@"绕过 TLS 校验" detail:@"仅用于已授权测试环境" control:&sslSwitch defaultOn:YES]];
    [form addArrangedSubview:[self switchRow:@"绕过业务签名" detail:@"匹配当前 direct profile" control:&signatureSwitch defaultOn:YES]];
    [form addArrangedSubview:[self switchRow:@"包含遥测域名" detail:@"关闭时保留更新与遥测直连" control:&passthroughSwitch defaultOn:NO]];
    [form addArrangedSubview:[self switchRow:@"游戏内悬浮窗" detail:@"战斗 Tick、抓包与 Trainer 快捷控制" control:&overlaySwitch defaultOn:YES]];
    [form addArrangedSubview:[self switchRow:@"悬浮窗滚动日志" detail:@"关闭后默认使用紧凑面板，磁盘日志仍会完整保存" control:&logConsoleSwitch defaultOn:YES]];
    [form addArrangedSubview:[self switchRow:@"不上传战斗记录" detail:@"拦截 battleFinish 与 saveBattleReplay 请求并在本地返回空奖励响应" control:&battleFinishBlockSwitch defaultOn:NO]];
    [form addArrangedSubview:[self switchRow:@"Trainer 控制" detail:@"在游戏悬浮窗中控制功能及 Tick/帧暂停步进" control:&trainerSwitch defaultOn:NO]];
    _sslSwitch = sslSwitch;
    _signatureSwitch = signatureSwitch;
    _passthroughSwitch = passthroughSwitch;
    _overlaySwitch = overlaySwitch;
    _logConsoleSwitch = logConsoleSwitch;
    _battleFinishBlockSwitch = battleFinishBlockSwitch;
    _trainerSwitch = trainerSwitch;
    [_trainerSwitch addTarget:self action:@selector(trainerChanged) forControlEvents:UIControlEventValueChanged];

    UIView *gadgetCard = [self card];
    UIStackView *gadgetStack = [self stackInCard:gadgetCard];
    [content addArrangedSubview:gadgetCard];
    [gadgetStack addArrangedSubview:[self sectionLabel:@"GADGET INSTALLATION"]];
    _gadgetStatusLabel = [self label:@"正在检查目标 App 的 Gadget 状态…" size:12 weight:UIFontWeightRegular color:OBSecondary()];
    _gadgetStatusLabel.numberOfLines = 0;
    [gadgetStack addArrangedSubview:_gadgetStatusLabel];
    UIStackView *gadgetActions = [UIStackView new];
    gadgetActions.axis = UILayoutConstraintAxisHorizontal;
    gadgetActions.spacing = 10;
    gadgetActions.distribution = UIStackViewDistributionFillEqually;
    _installGadgetButton = [self secondaryButton:@"安装 / 修复" action:@selector(installGadget) destructive:NO];
    _removeGadgetButton = [self secondaryButton:@"移除 Gadget" action:@selector(removeGadget) destructive:YES];
    [gadgetActions addArrangedSubview:_installGadgetButton];
    [gadgetActions addArrangedSubview:_removeGadgetButton];
    [gadgetStack addArrangedSubview:gadgetActions];

    _launchButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_launchButton setTitle:@"自动安装并启动" forState:UIControlStateNormal];
    _launchButton.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBold];
    [_launchButton setTitleColor:OBBackground() forState:UIControlStateNormal];
    _launchButton.backgroundColor = OBAccent();
    _launchButton.layer.cornerRadius = 14;
    [_launchButton.heightAnchor constraintEqualToConstant:54].active = YES;
    [_launchButton addTarget:self action:@selector(startSession) forControlEvents:UIControlEventTouchUpInside];
    [content addArrangedSubview:_launchButton];

    UIView *statusCard = [self card];
    UIStackView *statusStack = [self stackInCard:statusCard];
    [content addArrangedSubview:statusCard];
    UIStackView *statusHeader = [UIStackView new];
    statusHeader.axis = UILayoutConstraintAxisHorizontal;
    statusHeader.alignment = UIStackViewAlignmentCenter;
    [statusStack addArrangedSubview:statusHeader];
    [statusHeader addArrangedSubview:[self sectionLabel:@"SESSION STATUS"]];
    UIButton *openLogs = [UIButton buttonWithType:UIButtonTypeSystem];
    [openLogs setTitle:@"打开日志位置" forState:UIControlStateNormal];
    [openLogs setTitleColor:OBAccent() forState:UIControlStateNormal];
    openLogs.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    openLogs.accessibilityLabel = @"在文件 App 中打开日志位置";
    [openLogs addTarget:self action:@selector(openLogLocation) forControlEvents:UIControlEventTouchUpInside];
    [statusHeader addArrangedSubview:openLogs];
    UIButton *stop = [UIButton buttonWithType:UIButtonTypeSystem];
    [stop setTitle:@"停止" forState:UIControlStateNormal];
    [stop setTitleColor:[UIColor colorWithRed:1 green:0.45 blue:0.45 alpha:1] forState:UIControlStateNormal];
    [stop addTarget:self action:@selector(stopSession) forControlEvents:UIControlEventTouchUpInside];
    [statusHeader addArrangedSubview:stop];
    _statusLabel = [self label:@"尚未启动。TrollStore Gadget 后端会自动安装或修复内置 Gadget。" size:12 weight:UIFontWeightRegular color:OBSecondary()];
    _statusLabel.numberOfLines = 0;
    _statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    [statusStack addArrangedSubview:_statusLabel];

    OBPrepareUserLogPaths();
    [self prepareUserLogDirectory];
    [self restoreSettings];
    [self backendChanged];
    [self refreshGadgetStatus];
    [self refreshLog];
    _logTimer = [NSTimer scheduledTimerWithTimeInterval:1 target:self selector:@selector(refreshLog) userInfo:nil repeats:YES];
}

- (UIButton *)secondaryButton:(NSString *)title action:(SEL)action destructive:(BOOL)destructive {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:title forState:UIControlStateNormal];
    UIColor *color = destructive ? [UIColor colorWithRed:1 green:0.45 blue:0.45 alpha:1] : OBAccent();
    [button setTitleColor:color forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    button.backgroundColor = [UIColor colorWithWhite:0 alpha:0.22];
    button.layer.cornerRadius = 11;
    button.layer.borderWidth = 1;
    button.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.10].CGColor;
    [button.heightAnchor constraintEqualToConstant:44].active = YES;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (UILabel *)label:(NSString *)text size:(CGFloat)size weight:(UIFontWeight)weight color:(UIColor *)color {
    UILabel *label = [UILabel new];
    label.text = text;
    label.textColor = color;
    label.font = [UIFont systemFontOfSize:size weight:weight];
    return label;
}

- (UILabel *)sectionLabel:(NSString *)text {
    UILabel *label = [self label:text size:12 weight:UIFontWeightSemibold color:OBAccent()];
    [label setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    return label;
}

- (UIView *)card {
    UIView *view = [UIView new];
    view.backgroundColor = OBCard();
    view.layer.cornerRadius = 18;
    view.layer.borderWidth = 1;
    view.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.08].CGColor;
    return view;
}

- (UIStackView *)stackInCard:(UIView *)card {
    UIStackView *stack = [UIStackView new];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 15;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:card.topAnchor constant:18],
        [stack.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:18],
        [stack.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-18],
        [stack.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-18],
    ]];
    return stack;
}

- (UITextField *)textField:(NSString *)label placeholder:(NSString *)placeholder {
    UITextField *field = [UITextField new];
    field.attributedPlaceholder = [[NSAttributedString alloc] initWithString:placeholder attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.43 alpha:1]}];
    field.textColor = UIColor.whiteColor;
    field.backgroundColor = [UIColor colorWithWhite:0 alpha:0.22];
    field.layer.cornerRadius = 12;
    field.layer.borderWidth = 1;
    field.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.10].CGColor;
    field.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    field.clearButtonMode = UITextFieldViewModeWhileEditing;
    field.delegate = self;
    field.accessibilityLabel = label;
    field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 13, 48)];
    field.leftViewMode = UITextFieldViewModeAlways;
    [field.heightAnchor constraintEqualToConstant:50].active = YES;
    return field;
}

- (UIView *)switchRow:(NSString *)title detail:(NSString *)detail control:(UISwitch **)outSwitch defaultOn:(BOOL)defaultOn {
    UIStackView *row = [UIStackView new];
    row.axis = UILayoutConstraintAxisHorizontal;
    row.alignment = UIStackViewAlignmentCenter;
    row.spacing = 12;
    UIStackView *copy = [UIStackView new];
    copy.axis = UILayoutConstraintAxisVertical;
    copy.spacing = 3;
    UILabel *detailLabel = [self label:detail size:12 weight:UIFontWeightRegular color:OBSecondary()];
    detailLabel.numberOfLines = 0;
    [copy addArrangedSubview:[self label:title size:15 weight:UIFontWeightMedium color:UIColor.whiteColor]];
    [copy addArrangedSubview:detailLabel];
    [row addArrangedSubview:copy];
    UISwitch *toggle = [UISwitch new];
    toggle.onTintColor = OBAccent();
    toggle.on = defaultOn;
    toggle.accessibilityLabel = title;
    [row addArrangedSubview:toggle];
    *outSwitch = toggle;
    return row;
}

- (BOOL)prepareUserLogDirectory {
    OBPrepareUserLogPaths();
    if (OBLogsDirectory.length == 0) return NO;
    NSError *error = nil;
    BOOL created = [NSFileManager.defaultManager createDirectoryAtPath:OBLogsDirectory
                                             withIntermediateDirectories:YES
                                                              attributes:@{NSFilePosixPermissions: @0700}
                                                                   error:&error];
    if (!created) {
        _statusLabel.text = [NSString stringWithFormat:@"无法准备日志目录：%@", error.localizedDescription ?: @"未知错误"];
        return NO;
    }
    chmod(OBLogsDirectory.fileSystemRepresentation, 0700);
    return YES;
}

- (void)openLogLocation {
    [self.view endEditing:YES];
    if (![self prepareUserLogDirectory]) return;

    // UIDocumentPicker is the public Files.app integration point.  Setting
    // directoryURL makes the picker open directly at Documents/Logs instead
    // of forcing the user to search for the launcher folder every time.
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeItem]
                                                                      asCopy:NO];
    picker.delegate = self;
    picker.directoryURL = [NSURL fileURLWithPath:OBLogsDirectory isDirectory:YES];
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count == 0) return;
    _statusLabel.text = [NSString stringWithFormat:@"已选择日志文件：%@", urls.firstObject.lastPathComponent ?: @"未知文件"];
}

- (void)modeChanged {
    BOOL capture = _modeControl.selectedSegmentIndex == 1;
    _endpointField.accessibilityLabel = capture ? @"本机抓包不需要服务 URL" : @"重定向服务 URL";
    _endpointField.enabled = !capture;
    _endpointField.alpha = capture ? 0.45 : 1;
    NSString *placeholder = capture ? @"本机落盘，无需填写" : @"http://192.168.1.20:8443";
    _endpointField.attributedPlaceholder = [[NSAttributedString alloc] initWithString:placeholder attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.43 alpha:1]}];
}

- (void)trainerChanged {
    if (_trainerSwitch.on) _overlaySwitch.on = YES;
}

- (void)backendChanged {
    BOOL gadget = _backendControl.selectedSegmentIndex == 0;
    _installGadgetButton.enabled = gadget && !_injectorOperationRunning;
    _removeGadgetButton.enabled = gadget && !_injectorOperationRunning;
    [_launchButton setTitle:gadget ? @"自动安装并启动" : @"启动并注入" forState:UIControlStateNormal];
    if (!gadget) _gadgetStatusLabel.text = @"越狱 Frida 后端不修改目标 App bundle。";
}

- (void)backendControlChanged {
    [self backendChanged];
    if (_backendControl.selectedSegmentIndex == 0) [self refreshGadgetStatus];
}

- (void)bundleEditingEnded {
    if (_backendControl.selectedSegmentIndex == 0) [self refreshGadgetStatus];
}

- (void)restoreSettings {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    _bundleField.text = [defaults stringForKey:@"bundle_id"] ?: @"com.hypergryph.arknights";
    _endpointField.text = [defaults stringForKey:@"endpoint"] ?: @"";
    _backendControl.selectedSegmentIndex = [defaults integerForKey:@"backend"];
    if (_backendControl.selectedSegmentIndex < 0 || _backendControl.selectedSegmentIndex > 1)
        _backendControl.selectedSegmentIndex = 0;
    _modeControl.selectedSegmentIndex = [defaults integerForKey:@"mode"];
    if ([defaults objectForKey:@"bypass_ssl"]) _sslSwitch.on = [defaults boolForKey:@"bypass_ssl"];
    if ([defaults objectForKey:@"bypass_signatures"]) _signatureSwitch.on = [defaults boolForKey:@"bypass_signatures"];
    _passthroughSwitch.on = [defaults boolForKey:@"include_passthrough"];
    if ([defaults objectForKey:@"floating_gui"]) _overlaySwitch.on = [defaults boolForKey:@"floating_gui"];
    if ([defaults objectForKey:@"floating_log_console"]) _logConsoleSwitch.on = [defaults boolForKey:@"floating_log_console"];
    if ([defaults objectForKey:@"block_battle_finish_upload"]) _battleFinishBlockSwitch.on = [defaults boolForKey:@"block_battle_finish_upload"];
    if ([defaults objectForKey:@"trainer_enabled"]) _trainerSwitch.on = [defaults boolForKey:@"trainer_enabled"];
    [self trainerChanged];
    [self modeChanged];
}

- (NSString *)targetValidationError {
    NSString *bundle = [_bundleField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (bundle.length < 3 || [bundle containsString:@" "]) return @"Bundle ID 无效。";
    NSString *profilePath = [NSBundle.mainBundle pathForResource:@"profile" ofType:@"json"];
    NSData *profileData = profilePath != nil ? [NSData dataWithContentsOfFile:profilePath] : nil;
    NSDictionary *profile = profileData != nil ? [NSJSONSerialization JSONObjectWithData:profileData options:0 error:nil] : nil;
    NSString *profileBundle = [profile[@"bundle_id"] isKindOfClass:NSString.class] ? profile[@"bundle_id"] : nil;
    if (profileBundle.length == 0) return @"内置 direct profile 无效。";
    if (![bundle isEqualToString:profileBundle])
        return [NSString stringWithFormat:@"内置 profile 面向 %@，拒绝修改 %@。", profileBundle, bundle];
    return nil;
}

- (NSString *)validationError {
    NSString *targetError = [self targetValidationError];
    if (targetError != nil) return targetError;
    if (_modeControl.selectedSegmentIndex == 1) return nil;
    NSString *endpoint = [_endpointField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSURLComponents *components = [NSURLComponents componentsWithString:endpoint];
    BOOL schemeOK = [components.scheme isEqualToString:@"http"] || [components.scheme isEqualToString:@"https"];
    if (!components || !schemeOK || components.host.length == 0) return @"请填写包含 http:// 或 https:// 的完整服务 URL。";
    return nil;
}

- (void)startSession {
    [self.view endEditing:YES];
    NSString *validation = [self validationError];
    if (validation) { _statusLabel.text = validation; return; }
    if (_backendControl.selectedSegmentIndex == 0) {
        [self runInjectorCommand:@"install" completion:^(BOOL succeeded) {
            if (succeeded) [self startPreparedSession];
        }];
        return;
    }
    [self startPreparedSession];
}

- (void)startPreparedSession {
    [self.view endEditing:YES];
    NSString *validation = [self validationError];
    if (validation) { _statusLabel.text = validation; return; }
    if (![self prepareUserLogDirectory]) return;
    NSFileManager *files = NSFileManager.defaultManager;
    NSError *directoryError = nil;
    if (![files createDirectoryAtPath:OBStateDirectory withIntermediateDirectories:YES
                           attributes:@{NSFilePosixPermissions: @0700} error:&directoryError]) {
        _statusLabel.text = [NSString stringWithFormat:@"无法创建状态目录：%@", directoryError.localizedDescription];
        return;
    }
    chmod(OBStateDirectory.fileSystemRepresentation, 0700);
    if (![self terminateExistingHelper]) {
        _statusLabel.text = @"旧 helper 未能在 2 秒内退出；为避免重复注入，本次启动已取消。";
        return;
    }
    if (![self archiveCurrentLog]) {
        _statusLabel.text = @"无法归档上一会话日志；为避免日志丢失，本次启动已取消。";
        return;
    }
    NSError *logError = nil;
    if (![[NSData data] writeToFile:OBLogPath options:NSDataWritingAtomic error:&logError]) {
        _statusLabel.text = [NSString stringWithFormat:@"无法创建会话日志：%@", logError.localizedDescription ?: @"未知错误"];
        return;
    }
    chmod(OBLogPath.fileSystemRepresentation, 0600);
    [files removeItemAtPath:OBStatusPath error:nil];

    BOOL capture = _modeControl.selectedSegmentIndex == 1;
    NSString *bundle = [_bundleField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *endpoint = [_endpointField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSString *sessionID = NSUUID.UUID.UUIDString;
    NSString *backend = _backendControl.selectedSegmentIndex == 0 ? @"gadget" : @"server";
    NSDictionary *direct = @{
        @"no_proxy": @(capture), @"proxy_url": capture ? @"" : endpoint, @"capture": @(capture),
        @"proxy_encode_scheme": @NO,
        @"proxy_include_passthrough": @(_passthroughSwitch.on),
        @"bypass_ssl": @(_sslSwitch.on), @"bypass_signatures": @(_signatureSwitch.on),
        @"block_battle_finish_upload": @(_battleFinishBlockSwitch.on),
        @"capture_max_body_bytes": @4194304,
        @"floating_gui": @(_overlaySwitch.on || _trainerSwitch.on),
        @"floating_log_console": @(_logConsoleSwitch.on),
        @"battle_timeline": @YES,
        @"trainer_enabled": @(_trainerSwitch.on),
        @"trainer_target_fps": @120,
        @"trainer_battle_speed": @16
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{
        @"session_id": sessionID, @"backend": backend, @"bundle_id": bundle, @"direct": direct,
    } options:NSJSONWritingPrettyPrinted error:nil];
    NSString *configPath = [OBStateDirectory stringByAppendingPathComponent:@"current-config.json"];
    if (![json writeToFile:configPath options:NSDataWritingAtomic error:nil]) {
        _statusLabel.text = @"无法写入启动配置；请确认 IPA 通过 TrollStore 安装。";
        return;
    }
    chmod(configPath.fileSystemRepresentation, 0600);

    NSBundle *appBundle = NSBundle.mainBundle;
    NSString *helper = [appBundle pathForResource:@"OpenBachelorHelper" ofType:nil];
    NSString *script = [appBundle pathForResource:@"direct" ofType:@"js"];
    NSString *profile = [appBundle pathForResource:@"profile" ofType:@"json"];
    if (!helper || !script || !profile) { _statusLabel.text = @"IPA 资源不完整：缺少 helper、direct agent 或 profile。"; return; }

    char *argv[] = {(char *)helper.fileSystemRepresentation, (char *)configPath.fileSystemRepresentation,
        (char *)script.fileSystemRepresentation, (char *)profile.fileSystemRepresentation,
        (char *)OBLogPath.fileSystemRepresentation, NULL};
    pid_t pid = 0;
    int result = posix_spawn(&pid, helper.fileSystemRepresentation, NULL, NULL, argv, environ);
    if (result != 0) {
        _statusLabel.text = [NSString stringWithFormat:@"helper 启动失败：%s (%d)", strerror(result), result];
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    });
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setObject:bundle forKey:@"bundle_id"];
    [defaults setObject:endpoint forKey:@"endpoint"];
    [defaults setInteger:_backendControl.selectedSegmentIndex forKey:@"backend"];
    [defaults setInteger:_modeControl.selectedSegmentIndex forKey:@"mode"];
    [defaults setBool:_sslSwitch.on forKey:@"bypass_ssl"];
    [defaults setBool:_signatureSwitch.on forKey:@"bypass_signatures"];
    [defaults setBool:_passthroughSwitch.on forKey:@"include_passthrough"];
    [defaults setBool:_overlaySwitch.on forKey:@"floating_gui"];
    [defaults setBool:_logConsoleSwitch.on forKey:@"floating_log_console"];
    [defaults setBool:_battleFinishBlockSwitch.on forKey:@"block_battle_finish_upload"];
    [defaults setBool:_trainerSwitch.on forKey:@"trainer_enabled"];
    _activeSessionID = sessionID;
    _targetOpenedForSession = NO;
    _statusLabel.text = [backend isEqualToString:@"gadget"]
        ? @"helper 已启动，准备唤起 TrollStore Gadget 目标…"
        : @"helper 已启动，准备连接越狱环境的 frida-server…";
    if ([backend isEqualToString:@"gadget"]) {
        // Do not make launching depend on the first helper status poll. If a
        // stale or unrelated Frida service answers quickly, the helper may
        // leave its connecting state before the one-second UI timer fires.
        _targetOpenedForSession = YES;
        NSString *launchSessionID = [sessionID copy];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
            if ([self->_activeSessionID isEqualToString:launchSessionID])
                [self openTargetApplication];
        });
    }
}

- (void)installGadget {
    [self.view endEditing:YES];
    NSString *validation = [self targetValidationError];
    if (validation) { _gadgetStatusLabel.text = validation; return; }
    [self runInjectorCommand:@"install" completion:nil];
}

- (void)removeGadget {
    [self.view endEditing:YES];
    NSString *validation = [self targetValidationError];
    if (validation) { _gadgetStatusLabel.text = validation; return; }
    [self terminateExistingHelper];
    [self runInjectorCommand:@"remove" completion:nil];
}

- (void)refreshGadgetStatus {
    if (_injectorOperationRunning || _backendControl.selectedSegmentIndex != 0) return;
    NSString *validation = [self targetValidationError];
    if (validation) { _gadgetStatusLabel.text = validation; return; }
    [self runInjectorCommand:@"inspect" completion:nil];
}

- (void)runInjectorCommand:(NSString *)command completion:(void (^ _Nullable)(BOOL succeeded))completion {
    if (_injectorOperationRunning) return;
    NSString *bundle = [_bundleField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    _injectorOperationRunning = YES;
    _launchButton.enabled = NO;
    _installGadgetButton.enabled = NO;
    _removeGadgetButton.enabled = NO;
    if ([command isEqualToString:@"install"]) _gadgetStatusLabel.text = @"正在停止目标并原子安装、签名 Gadget…";
    else if ([command isEqualToString:@"remove"]) _gadgetStatusLabel.text = @"正在恢复原始 Mach-O 并移除 Gadget…";
    else _gadgetStatusLabel.text = @"正在检查 Gadget 和 Mach-O 备份状态…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSDictionary *result = OBRunInjector(command, bundle, &error);
        BOOL succeeded = [result[@"ok"] boolValue];
        NSString *message = succeeded ? result[@"message"] : (result[@"error"] ?: error.localizedDescription);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_injectorOperationRunning = NO;
            self->_launchButton.enabled = YES;
            [self backendChanged];
            self->_gadgetStatusLabel.text = message.length != 0 ? message : @"injector 未返回状态。";
            if (completion != nil) completion(succeeded);
        });
    });
}

- (void)openTargetApplication {
    NSString *bundle = [_bundleField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    SEL defaultSelector = NSSelectorFromString(@"defaultWorkspace");
    SEL openSelector = NSSelectorFromString(@"openApplicationWithBundleID:");
    BOOL opened = NO;
    if (workspaceClass && [workspaceClass respondsToSelector:defaultSelector]) {
        id workspace = ((id (*)(id, SEL))objc_msgSend)(workspaceClass, defaultSelector);
        if ([workspace respondsToSelector:openSelector])
            opened = ((BOOL (*)(id, SEL, id))objc_msgSend)(workspace, openSelector, bundle);
    }
    if (!opened) _statusLabel.text = @"系统拒绝自动打开目标应用；请从主屏幕手动打开，helper 会继续等待或保持会话。";
}

- (BOOL)terminateExistingHelper {
    NSString *text = [NSString stringWithContentsOfFile:OBHelperPIDPath encoding:NSUTF8StringEncoding error:nil];
    pid_t pid = (pid_t)text.intValue;
    char executablePath[OBProcPathSize] = {0};
    int length = pid > 1 ? proc_pidpath(pid, executablePath, sizeof(executablePath)) : 0;
    NSString *name = length > 0 ? [@(executablePath) lastPathComponent] : @"";
    if (![name isEqualToString:@"OpenBachelorHelper"] || kill(pid, 0) != 0) {
        [NSFileManager.defaultManager removeItemAtPath:OBHelperPIDPath error:nil];
        return YES;
    }
    if (kill(pid, SIGTERM) != 0) return NO;
    // Avoid attaching a second script while the previous helper is still unloading.
    for (NSUInteger attempt = 0; attempt < 40 && kill(pid, 0) == 0; attempt++)
        usleep(50000);
    BOOL stopped = kill(pid, 0) != 0;
    if (stopped) [NSFileManager.defaultManager removeItemAtPath:OBHelperPIDPath error:nil];
    return stopped;
}

- (void)stopSession {
    BOOL stopped = [self terminateExistingHelper];
    _activeSessionID = nil;
    _targetOpenedForSession = NO;
    _statusLabel.text = stopped ? @"helper 已停止；目标应用保持运行。" : @"helper 未能停止，请查看 session.log。";
}

- (void)refreshLog {
    NSDictionary *status = [self statusSnapshot];
    NSString *sessionID = [status[@"session_id"] isKindOfClass:NSString.class] ? status[@"session_id"] : nil;
    NSString *backend = [status[@"backend"] isKindOfClass:NSString.class] ? status[@"backend"] : nil;
    NSString *state = [status[@"state"] isKindOfClass:NSString.class] ? status[@"state"] : nil;
    NSString *message = [status[@"message"] isKindOfClass:NSString.class] ? status[@"message"] : nil;
    BOOL matchesActiveSession = _activeSessionID == nil || [sessionID isEqualToString:_activeSessionID];
    NSSet<NSString *> *liveStates = [NSSet setWithArray:@[@"starting", @"waiting_target", @"connecting", @"preparing", @"injecting", @"running", @"ready"]];
    BOOL helperRunning = [self statusProcessIsRunning:status];
    if (matchesActiveSession && state != nil && [liveStates containsObject:state] && !helperRunning)
        message = @"helper 已意外退出；请查看下方日志后重试。";
    NSString *log = [self logTail];
    NSArray<NSString *> *lines = [log componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    NSMutableArray<NSString *> *tail = [NSMutableArray array];
    for (NSString *line in lines.reverseObjectEnumerator) {
        if (line.length == 0) continue;
        [tail insertObject:line atIndex:0];
        if (tail.count == 5) break;
    }
    NSMutableArray<NSString *> *display = [NSMutableArray array];
    if (matchesActiveSession && message.length) [display addObject:message];
    if (tail.count) [display addObjectsFromArray:tail];
    if (display.count) _statusLabel.text = [display componentsJoinedByString:@"\n"];

    BOOL backendNeedsLaunch =
        ([backend isEqualToString:@"gadget"] &&
            ([state isEqualToString:@"waiting_target"] || [state isEqualToString:@"connecting"])) ||
        ([backend isEqualToString:@"server"] && [state isEqualToString:@"waiting_target"]);
    BOOL mayOpenTarget = helperRunning && (backendNeedsLaunch || [state isEqualToString:@"running"] ||
        [state isEqualToString:@"ready"]);
    if (_activeSessionID != nil && [sessionID isEqualToString:_activeSessionID] &&
        mayOpenTarget && !_targetOpenedForSession) {
        _targetOpenedForSession = YES;
        [self openTargetApplication];
    }
}

- (NSDictionary *)statusSnapshot {
    NSData *data = [NSData dataWithContentsOfFile:OBStatusPath];
    if (data.length == 0) return @{};
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}

- (NSString *)logTail {
    NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:OBLogPath error:nil];
    unsigned long long size = [attributes[NSFileSize] unsignedLongLongValue];
    if (size == 0) return @"";
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:OBLogPath];
    if (handle == nil) return @"";
    unsigned long long start = size > 5000 ? size - 5000 : 0;
    [handle seekToFileOffset:start];
    NSData *data = [handle readDataToEndOfFile];
    [handle closeFile];
    if (start != 0) {
        NSRange newline = [data rangeOfData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]
                                    options:0 range:NSMakeRange(0, data.length)];
        if (newline.location != NSNotFound && NSMaxRange(newline) < data.length)
            data = [data subdataWithRange:NSMakeRange(NSMaxRange(newline), data.length - NSMaxRange(newline))];
    }
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return text ?: @"";
}

- (BOOL)archiveCurrentLog {
    NSFileManager *files = NSFileManager.defaultManager;
    NSDictionary *attributes = [files attributesOfItemAtPath:OBLogPath error:nil];
    if (attributes == nil) return YES;
    if ([attributes[NSFileSize] unsignedLongLongValue] == 0) {
        return [files removeItemAtPath:OBLogPath error:nil];
    }
    NSError *directoryError = nil;
    if (![files createDirectoryAtPath:OBLogsDirectory withIntermediateDirectories:YES
                           attributes:@{NSFilePosixPermissions: @0700} error:&directoryError]) return NO;
    chmod(OBLogsDirectory.fileSystemRepresentation, 0700);
    NSDictionary *status = [self statusSnapshot];
    NSString *session = [status[@"session_id"] isKindOfClass:NSString.class]
        ? status[@"session_id"] : @"unknown";
    NSString *name = [NSString stringWithFormat:@"session-%.0f-%@.log",
                      [[NSDate date] timeIntervalSince1970], session];
    NSString *archivePath = [OBLogsDirectory stringByAppendingPathComponent:name];
    NSError *moveError = nil;
    if (![files moveItemAtPath:OBLogPath toPath:archivePath error:&moveError]) return NO;
    chmod(archivePath.fileSystemRepresentation, 0600);
    return YES;
}

- (BOOL)statusProcessIsRunning:(NSDictionary *)status {
    pid_t pid = [status[@"pid"] respondsToSelector:@selector(intValue)] ? [status[@"pid"] intValue] : 0;
    if (pid <= 1 || kill(pid, 0) != 0) return NO;
    char executablePath[OBProcPathSize] = {0};
    int length = proc_pidpath(pid, executablePath, sizeof(executablePath));
    return length > 0 && [[@(executablePath) lastPathComponent] isEqualToString:@"OpenBachelorHelper"];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if (textField == _bundleField && _endpointField.enabled) [_endpointField becomeFirstResponder];
    else [textField resignFirstResponder];
    return YES;
}

- (void)dealloc {
    [_logTimer invalidate];
}
@end

@interface OBAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation OBAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [OBLauncherViewController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(OBAppDelegate.class)); }
}
