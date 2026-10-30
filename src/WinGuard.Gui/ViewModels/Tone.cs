namespace WinGuard.Gui.ViewModels;

/// <summary>What an element means. Views bind this; the colour tokens follow from it.</summary>
public enum Tone
{
    /// <summary>No particular meaning.</summary>
    Neutral,

    /// <summary>Interactive or informational.</summary>
    Accent,

    /// <summary>Protected, healthy.</summary>
    Protected,

    /// <summary>Attacked, failed, destructive.</summary>
    Attack,

    /// <summary>Needs attention.</summary>
    Warn,
}

/// <summary>Which of the shared presentations a screen is in.</summary>
public enum ViewState
{
    /// <summary>Waiting for the first answer.</summary>
    Loading,

    /// <summary>Showing data.</summary>
    Ready,

    /// <summary>Answered, and there is nothing to show.</summary>
    Empty,

    /// <summary>The data could not be fetched and none is on hand.</summary>
    Error,
}
