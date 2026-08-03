using PasswordManager.Core.Models;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Works out where one account ends and the next begins inside a list of fields that were all
    /// typed into a single account.
    ///
    /// <para>Exists because people fill the form top to bottom and only notice the "several
    /// accounts" switch afterwards — a tester ended up with two logins in one card. The rule
    /// follows the order things are typed rather than trying to be clever: an account is complete
    /// once it has a password, so the next password, or the next identifier after that password,
    /// starts a new one.</para>
    ///
    /// <para>Pure and index-based so it can be tested on its own: it never sees a secret, only the
    /// shape of the fields.</para>
    /// </summary>
    public static class CredentialSplitter
    {
        private static bool IsIdentity(CredentialFieldType t) =>
            t is CredentialFieldType.Email or CredentialFieldType.Username or CredentialFieldType.Phone;

        /// <summary>
        /// Returns one account index per input field, in the same order. All zeros means the
        /// fields belong together and nothing should be split.
        /// </summary>
        public static IReadOnlyList<int> AssignAccounts(IReadOnlyList<CredentialFieldType> fields)
        {
            var assignment = new int[fields.Count];
            var account = 0;
            var countInAccount = 0;
            var accountHasPassword = false;

            for (var i = 0; i < fields.Count; i++)
            {
                var type = fields[i];
                var startsNew = countInAccount > 0 && accountHasPassword &&
                                (type == CredentialFieldType.Password || IsIdentity(type));

                if (startsNew)
                {
                    account++;
                    countInAccount = 0;
                    accountHasPassword = false;
                }

                assignment[i] = account;
                countInAccount++;
                if (type == CredentialFieldType.Password) accountHasPassword = true;
            }

            return assignment;
        }
    }
}
