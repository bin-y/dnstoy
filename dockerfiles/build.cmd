cd ..
docker build --cpu-shares=200 --memory=1024m -f dockerfiles\compile . -t dnstoy-compile
if errorlevel 1 (exit)
docker build -f dockerfiles\build . -t dnstoy
pause
