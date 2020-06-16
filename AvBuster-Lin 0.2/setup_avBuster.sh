chmod +x avbuster
apt-get install mono-complete golang -y
go get github.com/fatih/color
go get github.com/kbinani/screenshot
go get github.com/gorilla/mux
go get github.com/PuerkitoBio/goquery
go get golang.org/x/sys/windows
cd /root/go/src/github.com
mkdir lxn
cd lxn
git clone https://github.com/lxn/win
