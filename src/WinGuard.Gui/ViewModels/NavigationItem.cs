using CommunityToolkit.Mvvm.ComponentModel;

namespace WinGuard.Gui.ViewModels;

/// <summary>One entry in the left navigation; carries the view-model rendered in the content area.</summary>
public sealed partial class NavigationItem : ObservableObject
{
    /// <summary>Creates a navigation entry.</summary>
    /// <param name="title">Label shown in the navigation.</param>
    /// <param name="glyph">Icon.</param>
    /// <param name="shortcut">Number of the Ctrl+N shortcut.</param>
    /// <param name="viewModel">View-model whose matching view is shown when selected.</param>
    public NavigationItem(string title, string glyph, int shortcut, object viewModel)
    {
        Title = title;
        Glyph = glyph;
        Shortcut = shortcut;
        ViewModel = viewModel;
    }

    /// <summary>Label shown in the navigation.</summary>
    public string Title { get; }

    /// <summary>Icon.</summary>
    public string Glyph { get; }

    /// <summary>Number of the Ctrl+N shortcut.</summary>
    public int Shortcut { get; }

    /// <summary>View-model rendered in the content area when this entry is selected.</summary>
    public object ViewModel { get; }

    /// <summary>Small count beside the title (active bans); empty hides it.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccessibleName))]
    private string _badge = string.Empty;

    /// <summary>Marks unsaved work behind this page.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccessibleName))]
    private bool _hasAttention;

    /// <summary>Tooltip naming the keyboard shortcut.</summary>
    public string ToolTipText => $"{Title} (Ctrl+{Shortcut})";

    /// <summary>What a screen reader announces.</summary>
    public string AccessibleName
    {
        get
        {
            var name = Title;
            if (Badge.Length > 0)
            {
                name += ", " + Badge;
            }

            return HasAttention ? name + ", unsaved changes" : name;
        }
    }
}
