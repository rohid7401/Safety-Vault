namespace PasswordManager.UI.Abstractions
{
    /// <summary>A file chosen by the user: its display name and a readable stream.</summary>
    public sealed record PickedFile(string FileName, Stream Stream) : IDisposable
    {
        public void Dispose() => Stream.Dispose();
    }
}
