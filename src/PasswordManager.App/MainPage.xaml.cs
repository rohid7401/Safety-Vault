using PasswordManager.UI.Services;

namespace PasswordManager.App;

public partial class MainPage : ContentPage
{
	private readonly ShellBackNavigation _back;

	public MainPage(ShellBackNavigation back)
	{
		InitializeComponent();
		_back = back;
	}

	/// <summary>
	/// The whole app is one native page, so without this the device back button always leaves
	/// the app — even from a detail screen with somewhere to go back to. Returning true keeps
	/// the press; returning false lets the platform close the app, which is what should happen
	/// from the home screen.
	/// </summary>
	protected override bool OnBackButtonPressed() => _back.TryHandleBack();
}
