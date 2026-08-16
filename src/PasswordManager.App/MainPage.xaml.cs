namespace PasswordManager.App;

/// <summary>
/// The single native page hosting the BlazorWebView, so the platform back stack only ever holds
/// one entry and the router's own history lives inside the WebView.
///
/// <para>Bridging the device back button used to happen here, by overriding
/// <c>OnBackButtonPressed</c>. It does not any more: from API 35 Android enables predictive back
/// by default and that path never reaches the legacy callback, so the override sat here doing
/// nothing while every press closed the app. Android claims the press through
/// <c>OnBackPressedDispatcher</c> in MainActivity instead — see ShellBackCallback there.</para>
/// </summary>
public partial class MainPage : ContentPage
{
	public MainPage()
	{
		InitializeComponent();
	}
}
