local n=require("nixio")
local host,port,name=arg[1],tonumber(arg[2]),arg[3]
local qt=({A=1,AAAA=28})[arg[4] or "A"]
assert(host and port and name and qt)
name=name:lower():gsub("%.$","")
local function u16(x) return string.char(math.floor(x/256),x%256) end
local function r16(s,i) local a,b=s:byte(i,i+1); assert(a and b,"short DNS"); return a*256+b end
local labels={}; for label in name:gmatch("[^.]+") do assert(#label<=63); labels[#labels+1]=string.char(#label)..label end
local question=table.concat(labels).."\0"..u16(qt)..u16(1)
local sec,usec=n.gettimeofday(); local id=(sec+usec)%65536
local packet=u16(id)..u16(256)..u16(1)..u16(0)..u16(0)..u16(0)..question
local s=assert(n.socket(host:find(":") and "inet6" or "inet",arg[6]=="tcp" and "stream" or "dgram"))
local ok,reason=pcall(function()
 assert(s:setsockopt("socket","rcvtimeo",(arg[5]=="allow-response" or arg[5]=="health" or arg[5]=="positive") and 7 or 3,0)); assert(s:connect(host,tostring(port))); local data=arg[6]=="tcp" and (u16(#packet)..packet) or packet;assert(s:send(data)==#data)
 local function exact(count) local buf="";while #buf<count do local b=assert(s:recv(count-#buf),"DNS timeout");assert(#b>0);buf=buf..b end;return buf end
 local response
 if arg[6]=="tcp" then response=exact(r16(exact(2),1)) else response=assert(s:recv(4096),"DNS timeout") end; assert(#response>=12+#question)
 assert(r16(response,1)==id);local flags=r16(response,3)
 assert(math.floor(flags/32768)%2==1 and math.floor(flags/2048)%16==0 and math.floor(flags/512)%2==0)
 assert(r16(response,5)==1 and response:sub(13,12+#question)==question)
 local rc,answers=flags%16,r16(response,7);assert(rc==0 or (rc==3 and (arg[5]=="allow-nxdomain" or arg[5]=="health")) or (arg[5]=="allow-response" and (rc==2 or rc==3)),"rcode="..rc)
 if not arg[5] then assert(answers>0,"empty answer") end
 local pos=13+#question; local found=false
 for i=1,answers do
  while true do local len=response:byte(pos);assert(len);if len>=192 then pos=pos+2;break elseif len==0 then pos=pos+1;break else pos=pos+1+len end end
  local kind,cls,ttl,rdlen=r16(response,pos),r16(response,pos+2),r16(response,pos+4)*65536+r16(response,pos+6),r16(response,pos+8);pos=pos+10
  if cls==1 and kind==1 and rdlen==4 then local a,b,c,d=response:byte(pos,pos+3);print("ANSWER "..a.."."..b.."."..c.."."..d.." TTL="..ttl)
  elseif cls==1 and kind==28 and rdlen==16 then local parts={};for j=0,7 do parts[#parts+1]=string.format("%x",r16(response,pos+j*2)) end;print("ANSWER "..table.concat(parts,":").." TTL="..ttl) end
  if cls==1 and kind==qt and ((qt==1 and rdlen==4) or (qt==28 and rdlen==16)) then found=true end
  pos=pos+rdlen
 end
 if arg[5]=="positive" then assert(found,"missing requested address record") end
 print(string.format("OK %s %s rcode=%d answers=%d bytes=%d",name,arg[4] or "A",rc,answers,#response))
end)
s:close();if not ok then io.stderr:write(tostring(reason),"\n");os.exit(1) end
