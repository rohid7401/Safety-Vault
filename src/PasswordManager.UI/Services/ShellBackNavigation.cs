namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Bridges the device back button to the Blazor router.
    ///
    /// <para>The whole app lives inside a single native page, so the platform back stack only
    /// ever holds one entry: pressing back leaves the app even when there is somewhere to go back
    /// to. The router's history is inside the WebView, where the shell cannot see it.</para>
    ///
    /// <para>The shell must decide synchronously whether it consumed the press — returning "I
    /// handled it" and then discovering there was nowhere to go would swallow the press and trap
    /// the user in the app. So the layout keeps <see cref="CanHandleBack"/> up to date as a plain
    /// flag the shell can read on the spot, and the actual navigation happens on the renderer's
    /// thread once <see cref="BackPressed"/> is raised.</para>
    /// </summary>
    public sealed class ShellBackNavigation
    {
        /// <summary>
        /// Whether an in-app back action is currently available. Kept current by the layout;
        /// false means the press belongs to the platform, which will leave the app.
        /// </summary>
        public bool CanHandleBack { get; set; }

        /// <summary>
        /// Raised on the shell's thread when the user presses back and the app can handle it.
        /// Subscribers must marshal onto the renderer before touching component state.
        /// </summary>
        public event Action? BackPressed;

        /// <summary>Returns true when the press was consumed by the app.</summary>
        public bool TryHandleBack()
        {
            if (!CanHandleBack) return false;
            BackPressed?.Invoke();
            return true;
        }
    }
}
