using PasswordManager.UI.Services;

namespace PasswordManager.App;

public partial class App : Application
{
	// The vault keeps decrypted secrets in memory while unlocked, so leaving the app must
	// eventually close it — see VaultAutoLock for why the decision is taken on return rather
	// than on a timer while away.
	private readonly VaultAutoLock _autoLock;
	private readonly ShellBackNavigation _backNavigation;

	public App(VaultAutoLock autoLock, ShellBackNavigation backNavigation)
	{
		InitializeComponent();
		_autoLock = autoLock;
		_backNavigation = backNavigation;
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		return new Window(new MainPage(_backNavigation)) { Title = "PasswordManager.App" };
	}

	protected override void OnSleep()
	{
		base.OnSleep();
		_autoLock.OnBackground();
	}

	protected override void OnResume()
	{
		base.OnResume();
		_autoLock.OnForeground();
	}
}
