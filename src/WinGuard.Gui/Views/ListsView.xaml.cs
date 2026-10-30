using System.Windows;
using System.Windows.Controls;
using WinGuard.Gui.ViewModels;

namespace WinGuard.Gui.Views;

/// <summary>
/// Lists view (PLAN.md §9.5). The code-behind only forwards what WPF cannot bind: a list's selection,
/// and a paste into the add box, which becomes a reviewed bulk add when it holds several values.
/// </summary>
public partial class ListsView : System.Windows.Controls.UserControl
{
    /// <summary>Initializes the view.</summary>
    public ListsView() => InitializeComponent();

    private void OnAddBoxLoaded(object sender, RoutedEventArgs e)
    {
        var box = (TextBox)sender;
        DataObject.RemovePastingHandler(box, OnPasting);
        DataObject.AddPastingHandler(box, OnPasting);
    }

    private void OnPasting(object sender, DataObjectPastingEventArgs e)
    {
        if (sender is TextBox { DataContext: ListPanelViewModel panel }
            && e.SourceDataObject.GetData(DataFormats.UnicodeText) is string text
            && panel.TryPasteMany(text))
        {
            e.CancelCommand();
        }
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ListBox { DataContext: ListPanelViewModel panel } list)
        {
            panel.SetSelection(list.SelectedItems.OfType<ListRowViewModel>());
        }
    }
}
