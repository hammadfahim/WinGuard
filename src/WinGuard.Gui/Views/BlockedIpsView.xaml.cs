using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinGuard.Gui.Controls;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Views;

/// <summary>
/// Blocked IPs view (PLAN.md §9.2). Sorting and selection belong to the view-model; the code-behind
/// only forwards them from the grid, whose SelectedItems cannot be bound, and keeps a right-click on
/// an unselected row from acting on the old selection.
/// </summary>
public partial class BlockedIpsView : System.Windows.Controls.UserControl
{
    /// <summary>Initializes the view.</summary>
    public BlockedIpsView() => InitializeComponent();

    private BlockedIpsViewModel? ViewModel => DataContext as BlockedIpsViewModel;

    private void OnSorting(object sender, DataGridSortingEventArgs e)
    {
        // The view-model sorts, so the rows keep their order through a poll with no CollectionView.
        e.Handled = true;
        if (ViewModel is not { } viewModel || e.Column.SortMemberPath is not { Length: > 0 } column)
        {
            return;
        }

        var direction = viewModel.SortBy(column);
        foreach (var other in BansGrid.Columns)
        {
            other.SortDirection = null;
        }

        e.Column.SortDirection = direction;
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel?.SetSelection(BansGrid.SelectedItems.OfType<BanRowViewModel>());

    private void OnPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var row = Ui.FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row is null)
        {
            return;
        }

        // Right-clicking inside the selection keeps it, so the menu acts on all of it.
        if (!row.IsSelected)
        {
            BansGrid.SelectedItems.Clear();
            row.IsSelected = true;
        }

        row.Focus();
    }
}
