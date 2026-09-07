# Research sources

Primary protocol and storage reference:
[SandraK82/ypsopump-research](https://github.com/SandraK82/ypsopump-research),
reviewed at commit `de7e867241fafd2fb8061ceeecf42af2883b9eb4`.

- [Frida key extraction](https://github.com/SandraK82/ypsopump-research/blob/de7e867241fafd2fb8061ceeecf42af2883b9eb4/guides/frida-key-extraction.md)
- [Key exchange](https://github.com/SandraK82/ypsopump-research/blob/de7e867241fafd2fb8061ceeecf42af2883b9eb4/docs/04-key-exchange.md)
- [Key lifecycle](https://github.com/SandraK82/ypsopump-research/blob/de7e867241fafd2fb8061ceeecf42af2883b9eb4/docs/19-key-lifecycle-pump-rotation.md)
- [MAUI SecureStorage Android source](https://github.com/dotnet/maui/blob/main/src/Essentials/src/SecureStorage/SecureStorage.android.cs)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [Frida Android examples](https://frida.re/docs/examples/android/)

No source code from unlicensed third-party YpsoPump utilities is included.

Research sources disagree about whether the 28-day lifetime is app-side or
pump-enforced on all relevant firmware. This tool does not resolve that question:
it preserves source timestamps and always reports pump validity as unverified.
