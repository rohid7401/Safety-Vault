using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManager.Core.Models
{
    public class Vault
    {
        public int Id { get; set; }
        public List<Site> Sites { get; set; } = new();


    }
}
