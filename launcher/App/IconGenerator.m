#import <AppKit/AppKit.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        const NSInteger size = 1024;
        NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc]
            initWithBitmapDataPlanes:NULL pixelsWide:size pixelsHigh:size bitsPerSample:8
            samplesPerPixel:4 hasAlpha:YES isPlanar:NO
            colorSpaceName:NSCalibratedRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
        NSGraphicsContext *context = [NSGraphicsContext graphicsContextWithBitmapImageRep:bitmap];
        [NSGraphicsContext saveGraphicsState];
        [NSGraphicsContext setCurrentContext:context];

        NSRect canvas = NSMakeRect(0, 0, size, size);
        NSGradient *background = [[NSGradient alloc]
            initWithStartingColor:[NSColor colorWithRed:0.08 green:0.15 blue:0.20 alpha:1]
            endingColor:[NSColor colorWithRed:0.03 green:0.06 blue:0.09 alpha:1]];
        [background drawInRect:canvas angle:-45];

        NSBezierPath *ring = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(226, 226, 572, 572)];
        ring.lineWidth = 82;
        [[NSColor colorWithRed:0.15 green:0.25 blue:0.29 alpha:1] setStroke];
        [ring stroke];

        NSBezierPath *signal = [NSBezierPath bezierPath];
        [signal moveToPoint:NSMakePoint(301, 402)];
        [signal curveToPoint:NSMakePoint(723, 767)
               controlPoint1:NSMakePoint(405, 418)
               controlPoint2:NSMakePoint(544, 728)];
        signal.lineWidth = 70;
        signal.lineCapStyle = NSLineCapStyleRound;
        [[NSColor colorWithRed:0.28 green:0.96 blue:0.84 alpha:1] setStroke];
        [signal stroke];

        NSBezierPath *base = [NSBezierPath bezierPath];
        [base moveToPoint:NSMakePoint(323, 275)];
        [base lineToPoint:NSMakePoint(701, 275)];
        base.lineWidth = 70;
        base.lineCapStyle = NSLineCapStyleRound;
        [[NSColor colorWithWhite:0.97 alpha:1] setStroke];
        [base stroke];

        NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(658, 701, 132, 132)];
        [[NSColor colorWithRed:0.41 green:1 blue:0.89 alpha:1] setFill];
        [dot fill];

        [NSGraphicsContext restoreGraphicsState];
        NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        return [png writeToFile:@(argv[1]) atomically:YES] ? 0 : 1;
    }
}
