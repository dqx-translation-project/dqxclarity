using System.Globalization;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace DqxClarity.Views;

/// <summary>Maps log level string ("info"/"error") to the appropriate theme brush.</summary>
public class LevelToBrushConverter : IValueConverter
{
    public static readonly LevelToBrushConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string level && level == "error")
            return Application.Current?.Resources["AppDanger"] as IBrush
                   ?? Brushes.Red;
        return Application.Current?.Resources["AppText"] as IBrush
               ?? Brushes.White;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Progress fraction for the patch progress bar (downloaded / total).</summary>
public class PatchProgressConverter : IMultiValueConverter
{
    public static readonly PatchProgressConverter Instance = new();

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values is [long downloaded, long total] && total > 0)
            return (double)downloaded / total * 100.0;
        return 0.0;
    }
}

/// <summary>Returns true when the value equals the parameter string.</summary>
public class StringEqualConverter : IValueConverter
{
    public static readonly StringEqualConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is string s && s == (parameter as string);

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Returns true when the value does NOT equal the parameter string.</summary>
public class StringNotEqualConverter : IValueConverter
{
    public static readonly StringNotEqualConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => !(value is string s && s == (parameter as string));

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Returns true when the collection count is > 0.</summary>
public class CountToBoolConverter : IValueConverter
{
    public static readonly CountToBoolConverter Instance     = new();
    public static readonly CountIsZeroConverter IsZeroInstance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is int n && n > 0;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Returns true when the collection count is 0 (inverse of CountToBoolConverter).</summary>
public class CountIsZeroConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is int n && n == 0;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Maps bool to one of two strings. Use static instances for common cases.</summary>
public class BoolToStringConverter : IValueConverter
{
    private readonly string _trueVal, _falseVal;

    public BoolToStringConverter(string trueVal, string falseVal)
    {
        _trueVal  = trueVal;
        _falseVal = falseVal;
    }

    // "Validating…" vs "Validate Enabled Key"
    public static readonly BoolToStringConverter Validate =
        new("Validating…", "Validate Enabled Key");

    // "Loading…" vs "Read Database"
    public static readonly BoolToStringConverter DbLoad =
        new("Loading…", "Read Database");

    // "▼" (collapsed → click to expand) vs "▲" (expanded → click to collapse)
    public static readonly BoolToStringConverter BannerCollapse =
        new("▼", "▲");

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? _trueVal : _falseVal;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Extracts the nth value from a DbRow. ConverterParameter is the column index (int).</summary>
public class RowValueConverter : IValueConverter
{
    public static readonly RowValueConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is Models.DbRow row && parameter is int idx && idx < row.Values.Count)
            return row.Values[idx] ?? "";
        return "";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Truncates a string to at most ConverterParameter chars, appending an ellipsis when cut.</summary>
public class StringTruncateConverter : IValueConverter
{
    public static readonly StringTruncateConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string s) return value;
        var max = parameter switch
        {
            int n      => n,
            string str => int.TryParse(str, out var n2) ? n2 : 20,
            _          => 20,
        };
        return s.Length <= max ? s : s.Substring(0, max) + "…";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Maps bool to 1.0 (active) or 0.35 (inactive) opacity. Used for carousel dots.</summary>
public class BoolToOpacityConverter : IValueConverter
{
    public static readonly BoolToOpacityConverter DotInstance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? 1.0 : 0.35;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Maps bool to AppDanger or AppMuted brush.</summary>
public class BoolToBrushConverter : IValueConverter
{
    private readonly string _trueKey, _falseKey;

    public BoolToBrushConverter(string trueKey, string falseKey)
    {
        _trueKey  = trueKey;
        _falseKey = falseKey;
    }

    public static readonly BoolToBrushConverter ErrorOrMuted =
        new("AppDanger", "AppMuted");

    public static readonly BoolToBrushConverter ErrorOrSuccess =
        new("AppDanger", "AppSuccess");

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value is true ? _trueKey : _falseKey;
        return Application.Current?.Resources[key] as IBrush ?? Brushes.Gray;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
