using PasswordManager.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManager.Core.Services
{
    public class PasswordManagerService
    {
        private readonly Vault _vault;

        public PasswordManagerService(Vault vault) 
        {
            _vault = vault;
        }

        // Returns all sites
        public IEnumerable<Site> GetAllSites()
        {
            return _vault.Sites;
        }

        // Finds a site by name 
        public Site? GetSiteByName(string name)
        {
            return _vault.Sites
                .FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        }

        // Add a new Site
        public bool AddSite(string name, string? lable = null) 
        {
            if (GetSiteByName(name) != null) return false;

            _vault.Sites.Add(new Site
            { 
                Name = name,
                Label = lable
            });

            //_vault.LastUpdated = DateTime.UtcNow;    OCUPO ULTIMO TIEMPO EN SITE?
            return true;
        }

        // Deletes a site all its credentials
        public bool DeleteSite(string name)
        {
            var site = GetSiteByName(name);
            if (site != null) return false;

            _vault.Sites.Remove(site);
            //_vault.LastUpdated = DateTime.UtcNow;    OCUPO ULTIMO TIEMPO EN SITE?
            return true;

        }
    }
}
