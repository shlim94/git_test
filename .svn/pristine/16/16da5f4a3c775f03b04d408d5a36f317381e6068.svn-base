@echo off

chcp 65001

set JETTY_RUNNER_JAR=tools\downloads\jetty-runner-9.4.43.v20210629.jar
set PORT=8080
set JDWP_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8000

if not exist %JETTY_RUNNER_JAR% goto noJettyRunnerJar

if not exist target\WEB-INF\web.xml goto noWarContent

java -Xmx2048m -Dfile.encoding=UTF-8 -Djava.security.properties=tools\jetty\security\enableLegacyTLS.security %JDWP_OPTS% -jar %JETTY_RUNNER_JAR% --port %PORT% target

goto end

:noJettyRunnerJar
@echo =============================================================
@echo Jetty Runner Jar file doesn't exist at %JETTY_RUNNER_JAR% !!!
@echo -------------------------------------------------------------
@echo Please download it from the following URL and store it in tools\downloads\ folder.
@echo -------------------------------------------------------------
@echo   - https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-runner/9.4.43.v20210629/jetty-runner-9.4.43.v20210629.jar
@echo =============================================================
goto end

:noWarContent
@echo =============================================================
@echo Please run `ant web` before executing this command !!!
@echo =============================================================
goto end

:end
