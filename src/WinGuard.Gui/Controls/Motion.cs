using System.Windows;
using System.Windows.Media.Animation;

namespace WinGuard.Gui.Controls;

/// <summary>
/// The one place that decides whether anything moves. Windows' "show animations" setting is honoured
/// and high contrast never animates; everything else stays short and small, because RDP is the main
/// way this console is used and every animated frame is sent over the wire.
/// </summary>
public static class Motion
{
    private static readonly IEasingFunction Ease = new CubicEase { EasingMode = EasingMode.EaseOut };

    /// <summary>Whether animation is allowed right now.</summary>
    public static bool Enabled => SystemParameters.ClientAreaAnimation && !SystemParameters.HighContrast;

    /// <summary>Moves a dependency property to <paramref name="to"/>, instantly when motion is off.</summary>
    public static void To(IAnimatable target, DependencyProperty property, double to, int milliseconds = 180)
    {
        if (!Enabled)
        {
            target.BeginAnimation(property, null);
            if (target is DependencyObject element)
            {
                element.SetValue(property, to);
            }

            return;
        }

        target.BeginAnimation(property, new DoubleAnimation(to, TimeSpan.FromMilliseconds(milliseconds)) { EasingFunction = Ease });
    }

    /// <summary>
    /// Replaces the motion tokens with zero when Windows animations are off. Must run before the first
    /// template loads. The tokens are overwritten where they are defined, because a StaticResource
    /// resolves inside its own merged dictionary before it ever looks at the application's.
    /// </summary>
    public static void ApplyTokens(ResourceDictionary resources)
    {
        if (!Enabled)
        {
            ZeroTokens(resources);
        }
    }

    /// <summary>Forces every motion token to zero, wherever it is defined.</summary>
    public static void ZeroTokens(ResourceDictionary resources)
    {
        foreach (var merged in resources.MergedDictionaries)
        {
            ZeroTokens(merged);
        }

        foreach (var key in new[] { "MotionFast", "MotionMedium" })
        {
            if (resources.Keys.Cast<object>().Contains(key))
            {
                resources[key] = new Duration(TimeSpan.Zero);
            }
        }
    }
}
