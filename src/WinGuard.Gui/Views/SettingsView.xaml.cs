using System.Windows;
using System.Windows.Controls;

namespace WinGuard.Gui.Views;

/// <summary>
/// Settings view (PLAN.md §9.4). Logic lives in <c>SettingsViewModel</c>; the code-behind only
/// commits a grid cell that is still being edited before the Save command reads the rows.
/// </summary>
public partial class SettingsView : System.Windows.Controls.UserControl
{
    /// <summary>Initializes the view.</summary>
    public SettingsView() => InitializeComponent();

    // Button.Click is raised before the bound Command runs.
    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        foreach (var grid in new[] { FtpSourcesGrid, CustomSourcesGrid })
        {
            grid.CommitEdit(DataGridEditingUnit.Cell, exitEditingMode: true);
            grid.CommitEdit(DataGridEditingUnit.Row, exitEditingMode: true);
        }
    }
}
