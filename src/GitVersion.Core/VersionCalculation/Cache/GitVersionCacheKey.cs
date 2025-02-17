using GitVersion.Extensions;

namespace GitVersion.VersionCalculation.Cache;

public class GitVersionCacheKey
{
    public GitVersionCacheKey(string value)
    {
        if (value.IsNullOrEmpty())
            throw new ArgumentNullException(nameof(value));

        Value = value;
    }

    public string Value { get; private set; }
}
