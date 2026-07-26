namespace PasswordManager.Core.Exceptions
{
    /// <summary>
    /// An exception whose explanation is meant for the user, carried as a translatable
    /// <see cref="Code"/> rather than as prose. The UI resolves it against the active locale.
    /// </summary>
    public interface ILocalizedError
    {
        AppErrorCode Code { get; }

        /// <summary>Values substituted into the translated message, in order.</summary>
        object?[] Args { get; }
    }

    // The three below deliberately derive from the framework types they replace instead of
    // sharing one new base class. Callers already catch ArgumentException and
    // InvalidOperationException separately to tell "you typed something wrong" from "that
    // already exists", and UnauthorizedAccessException marks the failures that must never be
    // reported in detail. Keeping those identities means adding translation changed no
    // control flow anywhere.

    public sealed class LocalizedArgumentException : ArgumentException, ILocalizedError
    {
        public AppErrorCode Code { get; }
        public object?[] Args { get; }

        public LocalizedArgumentException(AppErrorCode code, params object?[] args)
            : base($"{code}") { Code = code; Args = args; }
    }

    public sealed class LocalizedInvalidOperationException : InvalidOperationException, ILocalizedError
    {
        public AppErrorCode Code { get; }
        public object?[] Args { get; }

        public LocalizedInvalidOperationException(AppErrorCode code, params object?[] args)
            : base($"{code}") { Code = code; Args = args; }
    }

    public sealed class LocalizedUnauthorizedAccessException : UnauthorizedAccessException, ILocalizedError
    {
        public AppErrorCode Code { get; }
        public object?[] Args { get; }

        public LocalizedUnauthorizedAccessException(AppErrorCode code, params object?[] args)
            : base($"{code}") { Code = code; Args = args; }

        public LocalizedUnauthorizedAccessException(AppErrorCode code, Exception inner, params object?[] args)
            : base($"{code}", inner) { Code = code; Args = args; }
    }
}
