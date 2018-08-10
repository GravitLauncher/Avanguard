using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using AvnApi;

namespace AvnSample
{
    class Program
    {
        static void Main(string[] args)
        {
            AvnApi.AvnApi.Load(@"Avanguard.dll");
            AvnApi.AvnApi.API.AvnStart();
            while (true) ;
        }
    }
}
