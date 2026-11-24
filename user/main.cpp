#include "app.h"
#include "util.h"

#include <string>

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    app::Options options;
    std::wstring error;
    if (!app::ParseArgs(argc, argv, options, error)) {
        util::Logf(util::Level::Error, L"%ls", error.c_str());
        app::PrintUsage();
        return 1;
    }

    if (options.mode == app::Mode::None) {
        app::PrintUsage();
        return 0;
    }

    util::SetVerbose(options.verbose);
    util::SetLogFile(util::JoinPath(util::ExeDirectory(), L"hwidspoof.log"));

    if (app::NeedsElevation(options) && !util::IsElevated()) {
        std::wstring commandLine;
        for (int index = 1; index < argc; index++) {
            if (!commandLine.empty()) {
                commandLine.push_back(L' ');
            }
            commandLine += util::QuoteArg(argv[index]);
        }
        util::Log(util::Level::Step, L"Requesting administrator rights");
        const int code = util::RelaunchElevated(commandLine);
        return code < 0 ? 1 : code;
    }

    return app::Run(options);
}
