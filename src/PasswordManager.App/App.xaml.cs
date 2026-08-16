using PasswordManager.UI.Services;

namespace PasswordManager.App;

public partial class App : Application
{
	// The vault keeps decrypted secrets in memory while unlocked, so leaving the app must
	// eventually close it — see VaultAutoLock for why the decision is taken on return rather
	// than on a timer while away.
	private readonly VaultAutoLock _autoLock;

	public App(VaultAutoLock autoLock)
	{
		InitializeComponent();
		_autoLock = autoLock;
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		return new Window(new MainPage()) { Title = "PasswordManager.App" };
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
