namespace WinGuard.Gui.ViewModels;

/// <summary>One entry in the left navigation list; carries the view-model rendered in the content area.</summary>
public sealed class NavigationItem
{
    /// <summary>Creates a navigation entry.</summary>
    /// <param name="title">Label shown in the navigation list.</param>
    /// <param name="viewModel">View-model whose matching view is shown when selected.</param>
    public NavigationItem(string title, object viewModel)
    {
        Title = title;
        ViewModel = viewModel;
    }

    /// <summary>Label shown in the navigation list.</summary>
    public string Title { get; }

    /// <summary>View-model rendered in the content area when this entry is selected.</summary>
    public object ViewModel { get; }
}