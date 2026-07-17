#include "ThreatGuard.h"
#include "Utilities.h"

int main() {
    Utilities::enableANSISupport();
    ThreatGuard app;
    app.run();
    return 0;
}
