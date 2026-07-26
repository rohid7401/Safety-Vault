using PasswordManager.UI.Abstractions;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="IPlatformInfo"/> backed by DeviceInfo.</summary>
    public class MauiPlatformInfo : IPlatformInfo
    {
        public bool HasFilesystemFolderAccess =>
            DeviceInfo.Platform != DevicePlatform.Android && DeviceInfo.Platform != DevicePlatform.iOS;
    }
}
