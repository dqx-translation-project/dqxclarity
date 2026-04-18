using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using DqxClarity.Launcher.Models;
using DqxClarity.Launcher.Services;
using DqxClarity.Launcher.ViewModels;

namespace DqxClarity.Launcher.Views;

public partial class SettingsView : UserControl
{
    private SettingsViewModel? _vm;

    public event Func<Task>? BrowseFolderRequested;
    public event Func<Task>? BrowseLeFolderRequested;

    private const string CommunityApiInfoText =
        "The Community API submits your translation strings to a shared remote database. " +
        "These strings are pooled across all contributors and help improve translations for the entire project.\n\n" +
        "To participate, you must meet the following requirement:\n\n" +
        "  • Both your player name and sibling name must be unique — not a common Japanese word, name, or in-game name.\n\n" +
        "If you meet this requirement and want to contribute, reach out to Serany (mebo) on Discord. " +
        "They'll verify your names and provide you with an API key to paste here.";

    private const string NameOverridesHelpText =
        "This tab lets you override how Japanese player and MyTown names are displayed.\n\n" +
        "If you encounter a player or MyTown name that dqxclarity mistranslates or renders incorrectly, " +
        "you can map the original Japanese name to a custom display name here.\n\n" +
        "Edit the JSON in the text box on the left. Use the example on the right as a guide.\n\n" +
        "• player_names — overrides player name display strings.\n" +
        "• mytown_names — overrides MyTown name display strings.\n\n" +
        "Click Save when done. Changes take effect on the next launch.";

    private const string DbHelpText =
        "dqxclarity caches every translation it produces into a local database so it doesn't have to re-translate the same text repeatedly.\n\n" +
        "If you encounter a bad translation or a string that breaks game functionality, you can remove it here instead of wiping your entire cache:\n\n" +
        "1. Click Read Database and select the dialog table from the dropdown.\n" +
        "2. Use the filter box to search for the offending text.\n" +
        "3. Check the box next to each row you want to remove.\n" +
        "4. Click Delete — the rows are removed and the database is saved immediately.\n\n" +
        "This lets you fix specific problem strings without losing the rest of your translation cache.\n\n" +
        "Note: only the dialog table supports row deletion. All other tables are for reference only and are automatically maintained by the dqxclarity team.";

    private const string GeneralConfigHelpText =
        "Nameplates\n" +
        "Translates the floating name tags that appear above players' and NPCs' heads from Japanese to English. " +
        "This only affects the in-world name display, not dialog boxes or menus.";

    private const string GeneralApiHelpText =
        "DeepL\n" +
        "Enables real-time machine translation of untranslated dialog and game text using your personal DeepL API key. " +
        "Produces higher-quality translations than Google for most content. A free-tier DeepL account is enough to get started.\n\n" +
        "Google Translate\n" +
        "Same as DeepL but uses Google Cloud Translate. Only one paid API service should be active at a time.\n\n" +
        "Free Google Translate\n" +
        "Uses an unofficial Google Translate endpoint that requires no API key. Easier to get started with, but may be rate-limited or stop working if you translate a large amount of text at once.\n\n" +
        "Validate Enabled Key\n" +
        "Sends a quick test request using your active API key to confirm it is recognized and working. Run this after entering or changing a key.";

    private const string AdvancedConfigHelpText =
        "Community Logging\n" +
        "Records untranslated or unknown in-game strings to a local text file. " +
        "Enabling this helps the translation team identify missing strings — " +
        "if you report a missing translation, they may ask you to share this log file.";

    private const string LoggingHelpText =
        "Enable Debug Logging\n" +
        "Turns on verbose diagnostic output written to the log file. Leave this off during normal play " +
        "and enable it only when troubleshooting a problem or when a developer asks you to collect extra information.\n\n" +
        "Open Log Folder\n" +
        "Opens the folder where dqxclarity stores its log files in your file explorer, " +
        "so you can quickly find and attach them when reporting issues.";

    private const string AdvancedApiHelpText =
        "Community API\n" +
        "Submits untranslated strings encountered during your session to the dqxclarity team's server " +
        "so they can be reviewed and added to the translation database. " +
        "This is a contributor feature — you will need a Community API key from the team. " +
        "Reach out to Serany (mebo) on Discord if you would like one.";

    private const string InstallationHelpText =
        "DQX Folder Path\n" +
        "The path to your DQX installation directory. dqxclarity needs this to find game executables " +
        "and DAT/IDX files for patching. Use the Browse button to select the folder — " +
        "it should be the DRAGON QUEST X folder inside your SquareEnix directory.\n\n" +
        "Locale Emulator Folder Path\n" +
        "The path to the folder where LEProc.exe is located. Locale Emulator emulates a Japanese locale, " +
        "which allows you to use the Japanese IME keyboard within DQX. " +
        "If this path is set, dqxclarity will launch DQX through LEProc.exe instead of directly. " +
        "This field is optional — leave it empty if you do not use Locale Emulator.\n\n" +
        "Install SendToChat\n" +
        "Downloads send_to_chat.exe from the latest GitHub release and saves it into the misc_files folder " +
        "inside your dqxclarity directory. SendToChat lets you send clipboard text into the DQX chat box. " +
        "You only need to do this once — the button will show a confirmation when the download finishes.";

    private const string LaunchHelpText =
        "Open DQX\n" +
        "Launches DQXBoot.exe — the standard DQX game client.\n\n" +
        "Open DQXConfig\n" +
        "Launches DQXConfig.exe, which lets you adjust in-game graphics and audio settings without opening the game itself.\n\n" +
        "Open SendToChat\n" +
        "Launches send_to_chat.exe directly. Only available after SendToChat has been installed via the Installation section.\n\n" +
        "Launch DQX with dqxclarity\n" +
        "When enabled, clicking Run will start DQX automatically alongside dqxclarity. " +
        "Useful if you want your full session to start with a single click.\n\n" +
        "Launch SendToChat with dqxclarity\n" +
        "When enabled, clicking Run will also start send_to_chat.exe alongside dqxclarity. " +
        "Requires SendToChat to be installed first.";

    private const string PatchHelpText =
        "Patch Launcher / Restore Launcher\n" +
        "Swaps the DQX launcher executable with an English-patched version, or restores the original Japanese file. " +
        "This only affects the launcher window's UI text and has no impact on gameplay.\n\n" +
        "Patch Config / Restore Config\n" +
        "Same as above but for DQXConfig.exe — patches or restores the configuration tool's interface text.\n\n" +
        "Patch Game Files\n" +
        "Downloads and applies the latest DAT/IDX translation mod to your game directory. " +
        "This is the main translation patch that enables in-game text translation. " +
        "Requires administrator rights and DQX must be fully closed before running.";

    public SettingsView()
    {
        InitializeComponent();
    }

    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        base.OnApplyTemplate(e);
    }

    // ── Hover hints ──────────────────────────────────────────────────────

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        if (_vm == null) return;

        var source = e.Source as Control;
        while (source != null && source != this)
        {
            var tip = ToolTip.GetTip(source) as string;
            if (!string.IsNullOrEmpty(tip))
            {
                if (_vm.HintText != tip) _vm.HintText = tip;
                return;
            }
            source = source.Parent as Control;
        }
        if (!string.IsNullOrEmpty(_vm.HintText)) _vm.HintText = "";
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        if (_vm != null) _vm.HintText = "";
    }

    // ── DataContext wiring ───────────────────────────────────────────────

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (DataContext is not SettingsViewModel vm) return;
        _vm = vm;

        // Populate theme combo
        if (ThemeCombo != null)
        {
            ThemeCombo.Items.Clear();
            foreach (var (id, label) in ThemeService.DarkThemes)
                ThemeCombo.Items.Add(new ComboBoxItem { Content = label, Tag = id });
            ThemeCombo.Items.Add(new ComboBoxItem { Content = "──── Light ────", IsEnabled = false });
            foreach (var (id, label) in ThemeService.LightThemes)
                ThemeCombo.Items.Add(new ComboBoxItem { Content = label, Tag = id });

            // Select current theme
            foreach (ComboBoxItem? item in ThemeCombo.Items)
            {
                if (item?.Tag as string == vm.SelectedTheme)
                {
                    ThemeCombo.SelectedItem = item;
                    break;
                }
            }
        }

        // Set active tab
        SwitchTab(vm.ActiveTab);

        // Track property changes
        vm.PropertyChanged += (_, args) =>
        {
            switch (args.PropertyName)
            {
                case nameof(SettingsViewModel.ActiveTab):
                    SwitchTab(vm.ActiveTab);
                    break;
                case nameof(SettingsViewModel.Validating) when ValidateBtn != null:
                    ValidateBtn.Content = vm.Validating ? "Validating…" : "Validate Enabled Key";
                    break;
                case nameof(SettingsViewModel.DbLoading) when ReadDbBtn != null:
                    ReadDbBtn.Content = vm.DbLoading ? "Loading…" : "Read Database";
                    break;
                case nameof(SettingsViewModel.SelectedTheme):
                    RefreshTableColors();
                    break;
                case nameof(SettingsViewModel.DbColumns):
                    RebuildTable();
                    break;
                case nameof(SettingsViewModel.DbFilteredRows):
                    OnFilteredRowsChanged();
                    break;
            }
        };

        // Show missing-key errors as a popup
        vm.ShowInfoRequested += async (title, body) =>
        {
            var win = TopLevel.GetTopLevel(this) as MainWindow;
            if (win != null) await win.ShowInfoAsync(title, body);
        };
    }

    private void SwitchTab(string tab)
    {
        if (PanelGeneral == null) return;
        // ScrollViewer hosts General, Advanced, and Game; hide it for full-height panels.
        var scrollable = tab is "general" or "advanced" or "game";
        if (TabScroll != null) TabScroll.IsVisible = scrollable;
        PanelGeneral.IsVisible   = tab == "general";
        PanelAdvanced.IsVisible  = tab == "advanced";
        PanelOverrides.IsVisible = tab == "nameoverrides";
        PanelDatabase.IsVisible  = tab == "database";
        PanelGame.IsVisible      = tab == "game";
        UpdateTabStyles(tab);
    }

    private void UpdateTabStyles(string active)
    {
        foreach (var btn in new[] { TabGeneral, TabAdvanced, TabOverrides, TabDatabase, TabGame })
        {
            if (btn == null) continue;
            btn.Classes.Set("tab-active", btn.Tag as string == active);
        }
    }

    private void OnTabClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
            _vm?.ActivateTabCommand.Execute(tag);
    }

    private void OnThemeSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item
            && item.Tag is string themeId && _vm != null)
        {
            _vm.SelectedTheme = themeId;
        }
    }

    private async void OnBrowseClick(object? sender, RoutedEventArgs e)
    {
        if (BrowseFolderRequested != null)
            await BrowseFolderRequested.Invoke();
    }

    private async void OnBrowseLeClick(object? sender, RoutedEventArgs e)
    {
        if (BrowseLeFolderRequested != null)
            await BrowseLeFolderRequested.Invoke();
    }

    private async void OnCommunityApiChanged(object? sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox cb || cb.IsChecked != true) return;
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Community API", CommunityApiInfoText);
    }

    private void OnDbTableSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox combo && combo.SelectedItem is string table)
            _ = _vm?.LoadDbTableCommand.ExecuteAsync(table);
    }

    // ── Virtual table ─────────────────────────────────────────────────────

    private const int MinRowHeight  = 26;
    private const int LineHeight    = 16;
    private const int RowVertPad    = 10;
    private const int CheckboxWidth = 30;
    private const int ColMinWidth   = 120;
    private const int Overscan      = 6;

    private int      _tableColWidth;
    private int      _tableColCount;
    private bool     _rebuildPending;
    private bool     _dialogMode;
    private int[]    _rowHeights = [];
    private double[] _rowOffsets = [];

    private readonly List<DbRow> _dbSelectedRows = [];

    // Re-applies theme brushes to already-rendered header and visible rows.
    // Called when the theme changes so colors update without a full rebuild.
    private void RefreshTableColors()
    {
        if (DbHeaderRow == null || DbCanvas == null || _vm == null) return;
        if (_tableColCount == 0) return;

        var mutedBrush = Application.Current?.Resources["AppMuted"] as IBrush ?? Brushes.Gray;
        foreach (var child in DbHeaderRow.Children)
        {
            if (child is TextBlock hdr)
                hdr.Foreground = mutedBrush;
        }

        RefreshVirtualRows();
    }

    // Full rebuild: re-creates header + resets canvas dimensions.
    // Called when the table changes (new table loaded).
    private void RebuildTable()
    {
        if (DbHeaderRow == null || DbCanvas == null || DbScroll == null || _vm == null) return;

        foreach (var r in _dbSelectedRows) r.Selected = false;
        _dbSelectedRows.Clear();
        UpdateDeleteButton();

        DbHeaderRow.ColumnDefinitions.Clear();
        DbHeaderRow.Children.Clear();
        DbCanvas.Children.Clear();

        var cols = _vm.DbColumns;
        _tableColCount = cols.Count;

        if (cols.Count == 0)
        {
            DbCanvas.Width  = 0;
            DbCanvas.Height = 0;
            return;
        }

        // Column width: fill viewport when possible, use minimum when too many columns
        var vpW = DbScroll.Bounds.Width;
        _tableColWidth = vpW > 10
            ? Math.Max(ColMinWidth, (int)(vpW - CheckboxWidth) / cols.Count)
            : ColMinWidth;
        var totalW = CheckboxWidth + cols.Count * _tableColWidth;

        // Header columns
        DbHeaderRow.ColumnDefinitions.Add(new ColumnDefinition(CheckboxWidth, GridUnitType.Pixel));
        var mutedBrush = Application.Current?.Resources["AppMuted"] as IBrush ?? Brushes.Gray;
        for (int i = 0; i < cols.Count; i++)
        {
            DbHeaderRow.ColumnDefinitions.Add(new ColumnDefinition(_tableColWidth, GridUnitType.Pixel));
            var hdr = new TextBlock
            {
                Text              = cols[i],
                FontSize          = 11,
                FontWeight        = FontWeight.SemiBold,
                Foreground        = mutedBrush,
                Padding           = new Thickness(6, 0),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming      = TextTrimming.CharacterEllipsis,
            };
            Grid.SetColumn(hdr, i + 1);
            DbHeaderRow.Children.Add(hdr);
        }

        _dialogMode = _vm.DbSelectedTable is "dialog" or "quests" or "story_so_far" or "walkthrough";
        ComputeRowMetrics(_vm.DbFilteredRows);
        DbHeaderRow.Width = totalW;
        DbCanvas.Width    = totalW;
        DbCanvas.Height   = _rowOffsets.Length > 1 ? _rowOffsets[^1] : 0;

        if (DbScroll.Offset != default)
            DbScroll.Offset = new Vector(0, 0);

        if (vpW <= 10 && !_rebuildPending)
        {
            // Layout not yet done — schedule a rebuild after the first layout pass
            _rebuildPending = true;
            DbScroll.LayoutUpdated += OnDbScrollFirstLayout;
        }
        else
        {
            RefreshVirtualRows();
        }
    }

    private void OnDbScrollFirstLayout(object? sender, EventArgs e)
    {
        if (DbScroll == null || DbScroll.Bounds.Width <= 10) return;
        DbScroll.LayoutUpdated -= OnDbScrollFirstLayout;
        _rebuildPending = false;
        RebuildTable();
    }

    // Light update: only adjusts canvas height and re-renders visible rows.
    // Called when the filter changes (preserving columns / header).
    private void OnFilteredRowsChanged()
    {
        if (DbCanvas == null || DbScroll == null || _vm == null) return;
        if (_tableColCount == 0) return;

        foreach (var r in _dbSelectedRows) r.Selected = false;
        _dbSelectedRows.Clear();
        UpdateDeleteButton();

        ComputeRowMetrics(_vm.DbFilteredRows);
        DbCanvas.Height = _rowOffsets.Length > 1 ? _rowOffsets[^1] : 0;

        if (_rebuildPending) return;

        DbScroll.Offset = new Vector(DbScroll.Offset.X, 0);
        RefreshVirtualRows();
    }

    private void ComputeRowMetrics(IReadOnlyList<DbRow> rows)
    {
        _rowHeights = new int[rows.Count];
        _rowOffsets = new double[rows.Count + 1];
        _rowOffsets[0] = 0;
        for (int i = 0; i < rows.Count; i++)
        {
            var lineCount = rows[i].Values
                .Select(v => (v ?? "").Count(c => c == '\n') + 1)
                .DefaultIfEmpty(1).Max();
            _rowHeights[i]      = Math.Max(MinRowHeight, lineCount * LineHeight + RowVertPad);
            _rowOffsets[i + 1]  = _rowOffsets[i] + _rowHeights[i];
        }
    }

    // Binary search: returns the index of the last row whose top offset is <= y.
    private int BinarySearchOffset(double y)
    {
        int lo = 0, hi = _rowOffsets.Length - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (_rowOffsets[mid] <= y) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    // Renders only the rows currently visible in the viewport (+ overscan).
    private void RefreshVirtualRows()
    {
        if (DbCanvas == null || DbScroll == null || _vm == null) return;

        var rows = _vm.DbFilteredRows;
        DbCanvas.Children.Clear();

        if (rows.Count == 0 || _tableColCount == 0) return;

        var scrollY  = DbScroll.Offset.Y;
        var viewH    = Math.Max(DbScroll.Bounds.Height, 100.0);
        if (_rowOffsets.Length < 2) return;
        var first    = Math.Max(0,          BinarySearchOffset(scrollY) - Overscan);
        var last     = Math.Min(rows.Count, BinarySearchOffset(scrollY + viewH) + Overscan + 1);

        var textBrush   = Application.Current?.Resources["AppText"]   as IBrush ?? Brushes.White;
        var borderBrush = Application.Current?.Resources["AppBorder"] as IBrush ?? Brushes.Gray;
        var canvasW     = DbCanvas.Width;

        for (int i = first; i < last; i++)
        {
            var ctrl = MakeVirtualRow(rows[i], _rowHeights[i], textBrush, borderBrush, canvasW);
            Canvas.SetTop(ctrl, _rowOffsets[i]);
            DbCanvas.Children.Add(ctrl);
        }
    }

    private Control MakeVirtualRow(DbRow row, int rowHeight, IBrush textBrush, IBrush borderBrush, double width)
    {
        var grid = new Grid { Width = width, Height = rowHeight };
        grid.ColumnDefinitions.Add(new ColumnDefinition(CheckboxWidth, GridUnitType.Pixel));
        for (int i = 0; i < _tableColCount; i++)
            grid.ColumnDefinitions.Add(new ColumnDefinition(_tableColWidth, GridUnitType.Pixel));

        // Checkbox — top-aligned for multi-line dialog rows, centered for single-line rows
        var cb = new CheckBox
        {
            IsChecked           = row.Selected,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment   = _dialogMode ? VerticalAlignment.Top : VerticalAlignment.Center,
            Margin              = _dialogMode ? new Thickness(0, 5, 0, 0) : new Thickness(0),
            Padding             = new Thickness(0),
        };
        cb.IsCheckedChanged += (_, _) =>
        {
            row.Selected = cb.IsChecked == true;
            if (row.Selected)
            {
                if (!_dbSelectedRows.Contains(row)) _dbSelectedRows.Add(row);
            }
            else
            {
                _dbSelectedRows.Remove(row);
            }
            UpdateDeleteButton();
        };
        Grid.SetColumn(cb, 0);
        grid.Children.Add(cb);

        // Data cells
        for (int i = 0; i < _tableColCount; i++)
        {
            var text = i < row.Values.Count ? (row.Values[i] ?? "") : "";
            Control cell;
            if (_dialogMode)
            {
                cell = new SelectableTextBlock
                {
                    Text              = text,
                    FontSize          = 11,
                    Foreground        = textBrush,
                    Padding           = new Thickness(6, 4),
                    VerticalAlignment = VerticalAlignment.Top,
                    TextWrapping      = TextWrapping.Wrap,
                };
            }
            else
            {
                cell = new TextBlock
                {
                    Text              = text,
                    FontSize          = 11,
                    Foreground        = textBrush,
                    Padding           = new Thickness(6, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming      = TextTrimming.CharacterEllipsis,
                };
            }
            Grid.SetColumn(cell, i + 1);
            grid.Children.Add(cell);
        }

        return new Border
        {
            BorderBrush     = borderBrush,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Child           = grid,
        };
    }

    private void OnDbScrollChanged(object? sender, ScrollChangedEventArgs e)
    {
        // Keep header in sync horizontally
        if (DbHeaderScroll != null)
            DbHeaderScroll.Offset = new Vector(DbScroll?.Offset.X ?? 0, 0);

        RefreshVirtualRows();
    }

    private void UpdateDeleteButton()
    {
        if (DeleteBtn == null) return;
        var count = _dbSelectedRows.Count;
        DeleteBtn.IsEnabled = count > 0;
        DeleteBtn.Content   = count > 0 ? $"Delete ({count})" : "Delete";
    }

    private async void OnDeleteClick(object? sender, RoutedEventArgs e)
    {
        if (_vm == null || _dbSelectedRows.Count == 0) return;
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;

        foreach (var r in _vm.DbRows) r.Selected = false;
        foreach (var r in _dbSelectedRows) r.Selected = true;

        var ok = await win.ShowConfirmAsync("Delete rows", $"Delete {_dbSelectedRows.Count} selected row(s)?");
        if (ok)
        {
            _dbSelectedRows.Clear();
            await _vm.ConfirmDbDeleteCommand.ExecuteAsync(null);
        }
    }

    private async void OnPurgeClick(object? sender, RoutedEventArgs e)
    {
        if (_vm == null) return;
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;

        var ok = await win.ShowConfirmAsync("Purge database",
            "This will delete all rows from the dialog translation cache. Are you sure?");
        if (ok)
            await _vm.PurgeDialogCacheCommand.ExecuteAsync(null);
    }

    private async void OnRestoreGameFilesClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Restore Game Files", "Coming soon.");
    }

    private async void OnNameOverridesHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("About Name Overrides", NameOverridesHelpText);
    }

    private async void OnDbHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("About the Database tab", DbHelpText);
    }

    // ── Section help buttons ─────────────────────────────────────────────

    private async void OnGeneralConfigHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Configuration", GeneralConfigHelpText);
    }

    private async void OnGeneralApiHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("API Settings", GeneralApiHelpText);
    }

    private async void OnAdvancedConfigHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Configuration", AdvancedConfigHelpText);
    }

    private async void OnLoggingHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Logging", LoggingHelpText);
    }

    private async void OnAdvancedApiHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("API Settings", AdvancedApiHelpText);
    }

    private async void OnInstallationHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Installation", InstallationHelpText);
    }

    private async void OnLaunchHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Launch", LaunchHelpText);
    }

    private async void OnPatchHelpClick(object? sender, RoutedEventArgs e)
    {
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;
        await win.ShowInfoAsync("Patch", PatchHelpText);
    }

    // ── Sidebar footer ───────────────────────────────────────────────────

    private void OnAboutClick(object? sender, RoutedEventArgs e) =>
        (TopLevel.GetTopLevel(this) as MainWindow)?.OpenAbout();

    private void OnWikiClick(object? sender, RoutedEventArgs e) =>
        (TopLevel.GetTopLevel(this) as MainWindow)?.OpenWiki();

    private void OnSupportClick(object? sender, RoutedEventArgs e) =>
        (TopLevel.GetTopLevel(this) as MainWindow)?.OpenSupport();

    private async void OnUpdateClick(object? sender, RoutedEventArgs e)
    {
        if (_vm?.UpdateInfo == null) return;
        var win = TopLevel.GetTopLevel(this) as MainWindow;
        if (win == null) return;

        var confirmed = await win.ShowUpdateAsync(_vm.UpdateInfo);
        if (confirmed)
        {
            _vm.SetUpdateService(new UpdateService());
            await _vm.RunUpdaterCommand.ExecuteAsync(null);
        }
    }
}
