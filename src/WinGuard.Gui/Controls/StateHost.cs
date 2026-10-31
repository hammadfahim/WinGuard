using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Controls;

/// <summary>
/// Shows its content while the bound <see cref="ViewState"/> is Ready and the shared loading, empty or
/// error presentation otherwise, so every screen reports those states the same way.
/// </summary>
public sealed class StateHost : ContentControl
{
    /// <summary>Which state to present.</summary>
    public static readonly DependencyProperty StateProperty = DependencyProperty.Register(
        nameof(State), typeof(ViewState), typeof(StateHost), new PropertyMetadata(ViewState.Ready));

    /// <summary>Icon of the empty state.</summary>
    public static readonly DependencyProperty EmptyGlyphProperty = DependencyProperty.Register(
        nameof(EmptyGlyph), typeof(string), typeof(StateHost), new PropertyMetadata(string.Empty));

    /// <summary>Headline of the empty state.</summary>
    public static readonly DependencyProperty EmptyTitleProperty = DependencyProperty.Register(
        nameof(EmptyTitle), typeof(string), typeof(StateHost), new PropertyMetadata(string.Empty));

    /// <summary>Explanation of the empty state.</summary>
    public static readonly DependencyProperty EmptyTextProperty = DependencyProperty.Register(
        nameof(EmptyText), typeof(string), typeof(StateHost), new PropertyMetadata(string.Empty));

    /// <summary>Headline of the error state.</summary>
    public static readonly DependencyProperty ErrorTitleProperty = DependencyProperty.Register(
        nameof(ErrorTitle), typeof(string), typeof(StateHost), new PropertyMetadata("Not available"));

    /// <summary>Explanation of the error state.</summary>
    public static readonly DependencyProperty ErrorTextProperty = DependencyProperty.Register(
        nameof(ErrorText), typeof(string), typeof(StateHost), new PropertyMetadata(string.Empty));

    /// <summary>Text of the loading state.</summary>
    public static readonly DependencyProperty LoadingTextProperty = DependencyProperty.Register(
        nameof(LoadingText), typeof(string), typeof(StateHost), new PropertyMetadata("Loading…"));

    /// <summary>Runs behind the Retry button of the error state.</summary>
    public static readonly DependencyProperty RetryCommandProperty = DependencyProperty.Register(
        nameof(RetryCommand), typeof(ICommand), typeof(StateHost), new PropertyMetadata(null));

    /// <summary>Whether the loading bar moves (off when Windows animations are off).</summary>
    public static readonly DependencyProperty AnimateLoadingProperty = DependencyProperty.Register(
        nameof(AnimateLoading), typeof(bool), typeof(StateHost), new PropertyMetadata(false));

    static StateHost()
    {
        DefaultStyleKeyProperty.OverrideMetadata(typeof(StateHost), new FrameworkPropertyMetadata(typeof(StateHost)));
    }

    /// <summary>Creates the host.</summary>
    public StateHost() => AnimateLoading = Motion.Enabled;

    /// <summary>Gets or sets <see cref="StateProperty"/>.</summary>
    public ViewState State
    {
        get => (ViewState)GetValue(StateProperty);
        set => SetValue(StateProperty, value);
    }

    /// <summary>Gets or sets <see cref="EmptyGlyphProperty"/>.</summary>
    public string EmptyGlyph
    {
        get => (string)GetValue(EmptyGlyphProperty);
        set => SetValue(EmptyGlyphProperty, value);
    }

    /// <summary>Gets or sets <see cref="EmptyTitleProperty"/>.</summary>
    public string EmptyTitle
    {
        get => (string)GetValue(EmptyTitleProperty);
        set => SetValue(EmptyTitleProperty, value);
    }

    /// <summary>Gets or sets <see cref="EmptyTextProperty"/>.</summary>
    public string EmptyText
    {
        get => (string)GetValue(EmptyTextProperty);
        set => SetValue(EmptyTextProperty, value);
    }

    /// <summary>Gets or sets <see cref="ErrorTitleProperty"/>.</summary>
    public string ErrorTitle
    {
        get => (string)GetValue(ErrorTitleProperty);
        set => SetValue(ErrorTitleProperty, value);
    }

    /// <summary>Gets or sets <see cref="ErrorTextProperty"/>.</summary>
    public string ErrorText
    {
        get => (string)GetValue(ErrorTextProperty);
        set => SetValue(ErrorTextProperty, value);
    }

    /// <summary>Gets or sets <see cref="LoadingTextProperty"/>.</summary>
    public string LoadingText
    {
        get => (string)GetValue(LoadingTextProperty);
        set => SetValue(LoadingTextProperty, value);
    }

    /// <summary>Gets or sets <see cref="RetryCommandProperty"/>.</summary>
    public ICommand? RetryCommand
    {
        get => (ICommand?)GetValue(RetryCommandProperty);
        set => SetValue(RetryCommandProperty, value);
    }

    /// <summary>Gets or sets <see cref="AnimateLoadingProperty"/>.</summary>
    public bool AnimateLoading
    {
        get => (bool)GetValue(AnimateLoadingProperty);
        set => SetValue(AnimateLoadingProperty, value);
    }
}
