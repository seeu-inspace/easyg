#!/usr/bin/env ruby
require 'json'

$vulns = JSON.parse('{"SSRF/OR":["dest=","redirect=","uri=","path=","continue=","url=","window=","next=","data=","reference=","site=","html=","val=","validate=","domain=","callback=","return=","page=","feed=","host=","port=","to=","out=","view=","dir=","target=","rurl=","destination=","redir=","redirect_uri=","redirect_url=","image_url=","go=","returnTo=","return_to=","checkout_url=","return_path="],
"SQLI":["id=","page=","report=","dir=","search=","category=","file=","class","url=","news=","item=","menu=","lang=","name=","ref=","title=","view=","topic=","thread=","type=","date=","form=","main=","nav=","region="],
"LFI":["cat=","dir=","action=","board=","date=","detail=","file=","download=","path","folder=","prefix=","include=","page=","inc=","locate=","show=","doc=","site=","type=","view=","content=","document=","layout=","mod=","conf="],
"RCE":["cmd=","exec=","command=","execute=","ping=","query=","jump=","code","reg=","do=","func=","arg=","option=","load=","process=","step=","read=","feature=","exe=","module=","payload=","run=","print="]}')

for i in 0..$vulns.keys.length-1 do
	File.open(ARGV[0],'r').each_line do |f|
		for j in 0..$vulns[$vulns.keys[i]].size-1 do
			if f.include? $vulns[$vulns.keys[i]][j]
				puts "[\e[32m+\e[0m] Possible " + $vulns.keys[i] + " found: " + f
			end
		end
	end
end
