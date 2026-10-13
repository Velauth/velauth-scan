namespace Velauth.Scan.Directory;

public sealed class DirectoryUnavailableException(string message, Exception? innerException = null)
    : Exception(message, innerException);
