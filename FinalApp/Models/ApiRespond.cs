using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FinalApp.Models
{
    public class ApiRespond
    {
        public bool Success { set; get; }
        public string Message { set; get; }
        public object Data { get; set; }
    }
}
