using System.Collections.Concurrent;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace OcSpike;

internal sealed record Navigation(string Uri, IReadOnlyList<(string Name, string Value)> Cookies, bool Closed);

/// <summary>Окно встроенного браузера для SAML SSO: каждую навигацию главного фрейма отдаёт в очередь.</summary>
internal sealed class SsoWindow : Form
{
    private readonly string _startUri;
    private readonly BlockingCollection<Navigation> _queue;
    private readonly string _userDataFolder;
    private readonly WebView2 _view = new() { Dock = DockStyle.Fill };
    private bool _closingByCode;

    public SsoWindow(string startUri, BlockingCollection<Navigation> queue, string userDataFolder)
    {
        _startUri = startUri;
        _queue = queue;
        _userDataFolder = userDataFolder;
        Text = "Вход AnyConnect — " + new Uri(startUri).Host;
        Width = 900;
        Height = 800;
        StartPosition = FormStartPosition.CenterScreen;
        Controls.Add(_view);
        Load += async (_, _) => await InitializeAsync();
        FormClosed += (_, _) =>
        {
            if (!_closingByCode)
                _queue.Add(new Navigation("", [], Closed: true));
        };
    }

    public void CloseByCode()
    {
        if (IsDisposed)
            return;
        BeginInvoke(() =>
        {
            _closingByCode = true;
            Close();
        });
    }

    private async Task InitializeAsync()
    {
        var environment = await CoreWebView2Environment.CreateAsync(null, _userDataFolder);
        await _view.EnsureCoreWebView2Async(environment);
        _view.CoreWebView2.NavigationCompleted += async (_, e) =>
        {
            var uri = _view.CoreWebView2.Source;
            var cookies = await _view.CoreWebView2.CookieManager.GetCookiesAsync(uri);
            var pairs = cookies.Select(c => (c.Name, c.Value)).ToList();
            Program.Log($"[sso] навигация {Program.RedactUri(uri)} успех={e.IsSuccess} http={e.HttpStatusCode} cookies=[{string.Join(",", pairs.Select(p => p.Name))}]");
            _queue.Add(new Navigation(uri, pairs, Closed: false));
        };
        _view.CoreWebView2.Navigate(_startUri);
    }
}
