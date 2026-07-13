using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IPasswordGenerator
    {
        /// <summary>
        /// Produce a password from the options. Throws
        /// <see cref="Exceptions.GeneratorConstraintException"/> if the options conflict
        /// (call <see cref="Validate"/> first to surface a friendly warning).
        /// </summary>
        string Generate(PasswordGeneratorOptions? options = null);

        int CalculateStrength(string password);

        /// <summary>Return the ways the options currently contradict each other (empty when satisfiable).</summary>
        IReadOnlyList<GeneratorConflict> Validate(PasswordGeneratorOptions options);

        /// <summary>Mutate the options in place to remove all conflicts, keeping the user's intent where possible.</summary>
        void ResolveConflicts(PasswordGeneratorOptions options);
    }
}
