using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace WinGuard.Gui.Views;

/// <summary>
/// Blocked IPs view (PLAN.md §9.2). The code-behind only ensures a right-click selects the row
/// under the pointer so the context-menu commands act on the expected IP.
/// </summary>
public partial class BlockedIpsView : System.Windows.Controls.UserControl
{
    /// <summary>Initializes the view.</summary>
    public BlockedIpsView() => InitializeComponent();

    private void OnPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var row = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row is not null)
        {
            row.IsSelected = true;
            row.Focus();
        }
    }

    private static T? FindAncestor<T>(DependencyObject? current)
        where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }
}