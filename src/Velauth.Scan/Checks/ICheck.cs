using Velauth.Scan.Directory;
using Velauth.Scan.Model;

namespace Velauth.Scan.Checks;

public interface ICheck
{
    Finding Run(IScanDirectory directory, DateTime nowUtc);
}
