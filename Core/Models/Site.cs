using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManager.Core.Models
{
    public class Site
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public List<Credential> Credentials { get; set; } = new();
        public string? Label { get; set; } = string.Empty;



    }
}
