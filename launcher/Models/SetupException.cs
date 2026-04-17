namespace DqxClarity.Launcher.Models;

/// <summary>
/// Thrown by SetupService when a setup step fails.
/// Carries both a user-facing message and the raw process output for debugging.
/// </summary>
public class SetupException : Exception
{
    /// <summary>Raw stdout/stderr captured from the failing process, or empty if unavailable.</summary>
    public string Detail { get; }

    public SetupException(string message, string detail = "") : base(message)
        => Detail = detail;
}
