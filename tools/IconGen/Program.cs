using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace WinGuard.Tools.IconGen;

/// <summary>
/// Draws every WinGuard icon from one vector source: the application icon, the three tray states
/// and the installer's wizard images. The silhouette is <c>ShieldGeometry</c> from Tokens.xaml, so
/// the icon and the logo inside the console are the same shield.
/// <para>
/// A small icon is not a large one scaled down: below <see cref="DetailFrom"/> the gradient and the
/// bevel would only blur, so those sizes are flat with a larger keyhole. The tray states differ in
/// shape as well as colour, so they can be told apart without seeing colour.
/// </para>
/// </summary>
internal static class Program
{
    private const string Shield = "M12,1.6 L21.4,5 L21.4,11.2 C21.4,17 17.6,20.9 12,22.8 C6.4,20.9 2.6,17 2.6,11.2 L2.6,5 Z";
    private const string ShieldInner = "M12,4.2 L19,6.75 L19,11.3 C19,15.65 16.2,18.6 12,20.2 C7.8,18.6 5,15.65 5,11.3 L5,6.75 Z";
    private const string Keyhole = "M12,6.9 A3.1,3.1 0 0 1 13.75,12.55 L14.6,16.9 C14.7,17.3 14.4,17.6 14,17.6 L10,17.6 C9.6,17.6 9.3,17.3 9.4,16.9 L10.25,12.55 A3.1,3.1 0 0 1 12,6.9 Z";
    private const string KeyholeBold = "M12,5.7 A3.8,3.8 0 0 1 14.25,12.55 L15.3,18.3 L8.7,18.3 L9.75,12.55 A3.8,3.8 0 0 1 12,5.7 Z";
    private const string Exclamation = "M10.1,5.6 L13.9,5.6 L13.3,13.6 L10.7,13.6 Z M12,14.9 A1.95,1.95 0 1 1 12,18.8 A1.95,1.95 0 1 1 12,14.9 Z";

    // The shield's extent inside its 24-unit box.
    private const double ShieldHeight = 21.2;
    private const double ShieldCentreY = 12.2;

    private const int DetailFrom = 32;
    private const int BevelFrom = 48;

    private static readonly int[] AppSizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];
    private static readonly int[] TraySizes = [16, 20, 24, 32, 40, 48];

    private static readonly Color Light = Rgb(0x62, 0xC6, 0xEA); // AccentBrush, dark theme
    private static readonly Color Deep = Rgb(0x0B, 0x6E, 0x99);  // AccentBrush, light theme
    private static readonly Color Rim = Rgb(0x07, 0x4B, 0x69);   // AccentPressedBrush, light theme
    private static readonly Color Flat = Rgb(0x14, 0x8F, 0xBE);  // Holds up on light and dark taskbars.
    private static readonly Color Offline = Rgb(0x74, 0x80, 0x8D);
    private static readonly Color Alert = Rgb(0xCF, 0x3A, 0x33);
    private static readonly Color Canvas = Rgb(0x0D, 0x11, 0x16);

    private enum TrayState
    {
        Protected,
        Offline,
        Alert,
    }

    [STAThread]
    private static int Main(string[] args)
    {
        var root = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
        var assets = Path.Combine(root, "installer", "assets");
        var gui = Path.Combine(root, "src", "WinGuard.Gui", "Assets");
        if (!Directory.Exists(assets))
        {
            Console.Error.WriteLine($"{assets} does not exist: run this from the repository root.");
            return 1;
        }

        Directory.CreateDirectory(gui);

        WriteIcon(Path.Combine(assets, "icon.ico"), AppSizes, AppIcon);
        WritePng(Path.Combine(assets, "icon-256.png"), AppIcon(256));
        File.WriteAllText(Path.Combine(assets, "icon.svg"), Svg(), new UTF8Encoding(false));

        WriteIcon(Path.Combine(gui, "tray-protected.ico"), TraySizes, size => Tray(size, TrayState.Protected));
        WriteIcon(Path.Combine(gui, "tray-offline.ico"), TraySizes, size => Tray(size, TrayState.Offline));
        WriteIcon(Path.Combine(gui, "tray-alert.ico"), TraySizes, size => Tray(size, TrayState.Alert));

        WriteBmp(Path.Combine(assets, "wizard-large-100.bmp"), WizardLarge(164, 314));
        WriteBmp(Path.Combine(assets, "wizard-large-200.bmp"), WizardLarge(328, 628));
        WriteBmp(Path.Combine(assets, "wizard-small-100.bmp"), WizardSmall(58));
        WriteBmp(Path.Combine(assets, "wizard-small-200.bmp"), WizardSmall(116));

        if (args.Length > 1)
        {
            WritePng(args[1], ContactSheet());
            Console.WriteLine($"Preview: {args[1]}");
        }

        Console.WriteLine("Icons written.");
        return 0;
    }

    // ---- the artwork ----

    private static RenderTargetBitmap AppIcon(int size) => Render(size, size, dc =>
    {
        // Room for the rim, which is drawn across the edge of the shield and would be cut off.
        var place = Placement(0, 0, size, size - (size < DetailFrom ? 1 : Math.Max(2, size * 0.05)));
        dc.PushTransform(place);
        if (size < DetailFrom)
        {
            dc.DrawGeometry(new SolidColorBrush(Flat), null, Geometry.Parse(Shield));
            dc.DrawGeometry(Brushes.White, null, Geometry.Parse(KeyholeBold));
        }
        else
        {
            DrawShield(dc, size);
        }

        dc.Pop();
    });

    /// <summary>The full shield: lit from the top, a darker right half, a rim, and at 48 and up a bevel.</summary>
    private static void DrawShield(DrawingContext dc, int size)
    {
        var shield = Geometry.Parse(Shield);
        dc.DrawGeometry(new LinearGradientBrush(Light, Deep, 90), null, shield);

        var right = new CombinedGeometry(GeometryCombineMode.Intersect, shield, new RectangleGeometry(new Rect(12, 0, 12, 24)));
        dc.DrawGeometry(new SolidColorBrush(Color.FromArgb(70, Rim.R, Rim.G, Rim.B)), null, right);

        dc.DrawGeometry(null, new Pen(new SolidColorBrush(Rim), 0.55) { LineJoin = PenLineJoin.Round }, shield);
        if (size >= BevelFrom)
        {
            dc.DrawGeometry(null, new Pen(new SolidColorBrush(Color.FromArgb(90, 255, 255, 255)), 0.32) { LineJoin = PenLineJoin.Round }, Geometry.Parse(ShieldInner));
        }

        dc.DrawGeometry(Brushes.White, null, Geometry.Parse(size >= BevelFrom ? Keyhole : KeyholeBold));
    }

    private static RenderTargetBitmap Tray(int size, TrayState state) => Render(size, size, dc =>
    {
        dc.PushTransform(Placement(0, 0, size, size - 1));
        var shield = Geometry.Parse(Shield);
        switch (state)
        {
            case TrayState.Protected:
                dc.DrawGeometry(new SolidColorBrush(Flat), null, shield);
                dc.DrawGeometry(Brushes.White, null, Geometry.Parse(KeyholeBold));
                break;

            case TrayState.Offline:
                // Hollow: nothing is known to be protected, and it reads as "off" without colour.
                var stroke = new SolidColorBrush(Offline);
                var width = ShieldHeight / (size - 1) * Math.Max(1.6, size / 11.0);
                dc.DrawGeometry(null, new Pen(stroke, width) { LineJoin = PenLineJoin.Round }, Geometry.Parse(ShieldInset));
                dc.DrawGeometry(stroke, null, Geometry.Parse(KeyholeBold));
                break;

            default:
                dc.DrawGeometry(new SolidColorBrush(Alert), null, shield);
                dc.DrawGeometry(Brushes.White, null, Geometry.Parse(Exclamation));
                break;
        }

        dc.Pop();
    });

    // The outline pulled in, so a stroked shield is as large as a filled one.
    private const string ShieldInset = "M12,2.7 L20.4,5.7 L20.4,11.2 C20.4,16.4 17,19.9 12,21.7 C7,19.9 3.6,16.4 3.6,11.2 L3.6,5.7 Z";

    private static RenderTargetBitmap WizardLarge(int width, int height) => Render(width, height, dc =>
    {
        dc.DrawRectangle(new LinearGradientBrush(Canvas, Rgb(0x14, 0x30, 0x3C), 90), null, new Rect(0, 0, width, height));

        var scale = width / 164.0;
        dc.PushTransform(Placement(width / 2.0 - (56 * scale), 74 * scale, 112 * scale, 112 * scale));
        DrawShield(dc, 256);
        dc.Pop();

        DrawText(dc, "WinGuard", 24 * scale, FontWeights.SemiBold, Colors.White, width / 2.0, 200 * scale);
        DrawText(dc, "Brute-force protection", 11 * scale, FontWeights.Normal, Light, width / 2.0, 234 * scale);
        DrawText(dc, "for Windows", 11 * scale, FontWeights.Normal, Light, width / 2.0, 249 * scale);
    });

    private static RenderTargetBitmap WizardSmall(int size) => Render(size, size, dc =>
    {
        dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, size, size));
        dc.PushTransform(Placement(size * 0.1, size * 0.1, size * 0.8, size * 0.8));
        DrawShield(dc, 256);
        dc.Pop();
    });

    private static void DrawText(DrawingContext dc, string text, double size, FontWeight weight, Color color, double centreX, double top)
    {
        var formatted = new FormattedText(
            text,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal),
            size,
            new SolidColorBrush(color),
            1.0);
        dc.DrawText(formatted, new Point(centreX - (formatted.Width / 2), top));
    }

    /// <summary>Maps the 24-unit shield to a square, centred, as tall as <paramref name="height"/> pixels.</summary>
    private static MatrixTransform Placement(double left, double top, double box, double height)
    {
        var scale = height / ShieldHeight;
        var matrix = new Matrix(scale, 0, 0, scale, left + (box / 2) - (12 * scale), top + (box / 2) - (ShieldCentreY * scale));
        return new MatrixTransform(matrix);
    }

    private static RenderTargetBitmap Render(int width, int height, Action<DrawingContext> draw)
    {
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            draw(dc);
        }

        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        bitmap.Freeze();
        return bitmap;
    }

    private static Color Rgb(byte r, byte g, byte b) => Color.FromRgb(r, g, b);

    // ---- the files ----

    /// <summary>An ICO with one frame per size: DIBs up to 128 for the tools that read no other kind, PNG at 256.</summary>
    private static void WriteIcon(string path, int[] sizes, Func<int, BitmapSource> frame)
    {
        var images = sizes.Select(size => (Size: size, Data: size >= 256 ? PngBytes(frame(size)) : DibBytes(frame(size), size))).ToList();

        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream);
        writer.Write((ushort)0);
        writer.Write((ushort)1);
        writer.Write((ushort)images.Count);

        var offset = 6 + (16 * images.Count);
        foreach (var image in images)
        {
            writer.Write((byte)(image.Size >= 256 ? 0 : image.Size));
            writer.Write((byte)(image.Size >= 256 ? 0 : image.Size));
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((ushort)1);
            writer.Write((ushort)32);
            writer.Write(image.Data.Length);
            writer.Write(offset);
            offset += image.Data.Length;
        }

        foreach (var image in images)
        {
            writer.Write(image.Data);
        }
    }

    /// <summary>A 32-bit DIB as ICO frames hold it: bottom-up, straight alpha, followed by a 1-bit mask.</summary>
    private static byte[] DibBytes(BitmapSource source, int size)
    {
        var straight = new FormatConvertedBitmap(source, PixelFormats.Bgra32, null, 0);
        var pixels = new byte[size * size * 4];
        straight.CopyPixels(pixels, size * 4, 0);

        var maskStride = ((size + 31) / 32) * 4;
        var mask = new byte[maskStride * size];

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(40);
        writer.Write(size);
        writer.Write(size * 2);
        writer.Write((ushort)1);
        writer.Write((ushort)32);
        writer.Write(0);
        writer.Write(pixels.Length + mask.Length);
        writer.Write(0);
        writer.Write(0);
        writer.Write(0);
        writer.Write(0);

        for (var y = size - 1; y >= 0; y--)
        {
            writer.Write(pixels, y * size * 4, size * 4);
            for (var x = 0; x < size; x++)
            {
                if (pixels[(y * size * 4) + (x * 4) + 3] == 0)
                {
                    mask[((size - 1 - y) * maskStride) + (x / 8)] |= (byte)(0x80 >> (x % 8));
                }
            }
        }

        writer.Write(mask);
        return stream.ToArray();
    }

    private static byte[] PngBytes(BitmapSource source)
    {
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(source));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        return stream.ToArray();
    }

    private static void WritePng(string path, BitmapSource source) => File.WriteAllBytes(path, PngBytes(source));

    private static void WriteBmp(string path, BitmapSource source)
    {
        var encoder = new BmpBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(new FormatConvertedBitmap(source, PixelFormats.Bgr24, null, 0)));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static string Svg()
    {
        var text = new StringBuilder();
        text.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" width=\"256\" height=\"256\">");
        text.AppendLine("  <title>WinGuard</title>");
        text.AppendLine($"  <defs><linearGradient id=\"lit\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"{Hex(Light)}\"/><stop offset=\"1\" stop-color=\"{Hex(Deep)}\"/></linearGradient>");
        text.AppendLine($"  <clipPath id=\"shield\"><path d=\"{Shield}\"/></clipPath></defs>");
        text.AppendLine($"  <path d=\"{Shield}\" fill=\"url(#lit)\"/>");
        text.AppendLine($"  <rect x=\"12\" y=\"0\" width=\"12\" height=\"24\" fill=\"{Hex(Rim)}\" fill-opacity=\"0.27\" clip-path=\"url(#shield)\"/>");
        text.AppendLine($"  <path d=\"{Shield}\" fill=\"none\" stroke=\"{Hex(Rim)}\" stroke-width=\"0.55\" stroke-linejoin=\"round\"/>");
        text.AppendLine($"  <path d=\"{ShieldInner}\" fill=\"none\" stroke=\"#FFFFFF\" stroke-opacity=\"0.35\" stroke-width=\"0.32\" stroke-linejoin=\"round\"/>");
        text.AppendLine($"  <path d=\"{Keyhole}\" fill=\"#FFFFFF\"/>");
        text.AppendLine("</svg>");
        return text.ToString();
    }

    private static string Hex(Color color) => $"#{color.R:X2}{color.G:X2}{color.B:X2}";

    /// <summary>Every size on light and dark, actual size and magnified, for checking by eye. Not shipped.</summary>
    private static RenderTargetBitmap ContactSheet()
    {
        const int width = 1500;
        const int height = 1010;
        return Render(width, height, dc =>
        {
            dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, width, height / 2));
            dc.DrawRectangle(new SolidColorBrush(Rgb(0x1F, 0x1F, 0x1F)), null, new Rect(0, height / 2, width, height / 2));
            for (var band = 0; band < 2; band++)
            {
                var top = band * (height / 2);
                var x = 20.0;
                foreach (var size in AppSizes)
                {
                    dc.DrawImage(AppIcon(size), new Rect(x, top + 16, size, size));
                    x += size + 20;
                }

                x = 20.0;
                foreach (var size in new[] { 16, 24, 32 })
                {
                    var zoom = 8;
                    DrawPixels(dc, AppIcon(size), x, top + 290, size * zoom);
                    x += (size * zoom) + 20;
                }

                x = 760.0;
                foreach (var state in Enum.GetValues<TrayState>())
                {
                    foreach (var size in new[] { 16, 24 })
                    {
                        dc.DrawImage(Tray(size, state), new Rect(x, top + 300, size, size));
                        DrawPixels(dc, Tray(size, state), x, top + 340, size * 6);
                        x += (size * 6) + 16;
                    }
                }
            }
        });
    }

    private static void DrawPixels(DrawingContext dc, BitmapSource source, double x, double y, double size)
    {
        var group = new DrawingGroup();
        RenderOptions.SetBitmapScalingMode(group, BitmapScalingMode.NearestNeighbor);
        group.Children.Add(new ImageDrawing(source, new Rect(x, y, size, size)));
        dc.DrawDrawing(group);
    }
}
