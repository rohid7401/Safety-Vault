using PasswordManager.Core.Models;

namespace PasswordManager.Core.Exceptions
{
    /// <summary>
    /// Thrown by the password generator when the requested options contradict each
    /// other (e.g. an included word longer than the total length, or an excluded
    /// character that the word needs). Callers can inspect <see cref="Conflicts"/>
    /// and offer to auto-resolve them.
    /// </summary>
    public class GeneratorConstraintException : Exception
    {
        public IReadOnlyList<GeneratorConflict> Conflicts { get; }

        public GeneratorConstraintException(IReadOnlyList<GeneratorConflict> conflicts)
            : base("The password generator options conflict with each other.")
        {
            Conflicts = conflicts;
        }
    }
}
