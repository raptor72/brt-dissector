BRT = Proto("BRT", "BRT Protocol")  
function BRT.dissector(buf, pinfo, tree)
    pinfo.cols.protocol = BRT.name
    local subtree = tree:add(BRT,buf(), "BRT lua") 
    
    local all_Payload_len = buf:len() -- length of payload all packet
    local first_packe_len = buf(0,2):uint() -- length of payload firsf brt message 
   
    local length = all_Payload_len  
    local start_i = 0 -- from this bit packet begining
    len_i = 0         -- number of bit from whom we finding message length 


    local errors = {[0]=" NO_ERROR (0x00000000)", [2]=" INSUFFICIEND_FUNDS (0x00000002)", [10]=" INTERNALL_ERROR (0x0000000a)", [14]=" DESTINATION_PROHIBITED (0x0000000e)", [19]=" LC_STATUS_BLOCKED (0x00000013)", [27]=" SERVICE_INACTIVE (0x0000001b)"}
    local rels = {[16]=" Normal Call Clearing (16)", [18]=" No user responding (18)", [21]=" Call rejected (21)", [28]=" Invalid number format (address incomplete) (28)", [126]=" Unknown (126)", [127]=" Interworking, unspecified (127)"}


    function err_handler(error)
        if errors[error:uint()] then
            subtree:add(error, "ErrorCode: " .. error:uint()):append_text(errors[error:uint()])
	else	
	    subtree:add(error, "ErrorCode: " .. error:uint()):append_text(" Undescribed Error Code")
	end
    end

    function rc_handler(rel)
	if rels[rel:uint()] then
	    subtree:add(rel, "ReleaseCause: " .. rel:uint()):append_text(rels[rel:uint()])
	else
	    subtree:add(rel, "ReleaseCause: " .. rel:uint()):append_text(" Undescribed Release Cause")
	end	
    end
    
    function tz_handler(tz)
        subtree:add(buf(tz+4,4), "Date: "  .. tostring(buf(tz+4,1)):reverse() .. tostring(buf(tz+5,1)):reverse() .. "/" .. tostring(buf(tz+6,1)):reverse() .. "/" .. tostring(buf(tz+7,1)):reverse())
        subtree:add(buf(tz+8,3), "Time: " .. tostring(buf(tz+8,1)):reverse() .. ":" .. tostring(buf(tz+9,1)):reverse() .. ":" .. tostring(buf(tz+10,1)):reverse())
        subtree:add(buf(tz+11,1), "Timezone: " .. buf(tz+11,1))
    end
    
    
    while length > 0 do            
	local len = buf(len_i,2):uint() -- payload length (bits count)
        local modo = len - 4    
            
        subtree:add(buf(start_i,2), "length: " .. buf(start_i,2):uint())
        subtree:add(buf(start_i+4,4), "sequence: " .. buf(start_i+4,4):uint())
        subtree:add(buf(start_i+12,16), "SessionID: " .. buf(start_i+12,16)) 
            
        subtree:add(buf(start_i+12,6), "    MSC GT: " .. buf(start_i+12,6))
        subtree:add(buf(start_i+20,4), "    TCAP TID MSC: " .. buf(start_i+20,4))
        subtree:add(buf(start_i+24,1), "    CG ID: " .. buf(start_i+24,1):uint())
        subtree:add(buf(start_i+25,1), "    BRT ID: " .. buf(start_i+25,1):uint())
        subtree:add(buf(start_i+26,2), "    Call counter: " .. buf(start_i+26,2):uint())
            
        local mtype = buf(start_i+2,2):le_uint()
	
        if mtype == 272 then
            pinfo.cols.info:set("Authorize Voice request") -- add text in column "Info" 
            subtree:add(buf(2,2), "Authorize voice requerst: " .. buf(2,2))    
            subtree:add(buf(32,4), "ServiceKey: " .. buf(32,4):uint())

            for i = 1,modo do
                if buf(start_i+i, 4):uint() == 655371 then --00:0a:00:0b
                    subtree:add(buf(start_i+i+4, 11), "CallingPartyNumber: " .. buf(start_i+i+4, 11):string())
                end

                if buf(start_i+i, 4):uint() == 524298 then --00:08:00:0a
                    subtree:add(buf(start_i+i+4, 11), "CalledPartyNumber: " .. buf(start_i+i+4, 11):string())
                end

                if buf(start_i+i, 4):uint() == 458763 then --00:07:00:0b
                    subtree:add(buf(start_i+i+4, 11), "CalledPartyBCDNumber: " .. buf(start_i+i+4, 11):string())
                end

                if buf(start_i+i, 4):uint() == 1507343 then -- 00:17:00:0f
                    subtree:add(buf(start_i+i+4,15), "IMSI: " .. buf(start_i+i+4, 15):string())
                end

                if buf(start_i+i, 4):uint() == 1966091 then -- 00:1e:00:0b
                    subtree:add(buf(start_i+i+4,11), "MSC Adress: " .. buf(start_i+i+4,11):string())
                end

                if buf(start_i+i, 4):uint() == 3145736 then -- 00:30:00:08
		    local tz = start_i+i
                    tz_handler(tz)
                end
            end  		


        elseif mtype == 528 then			
	    pinfo.cols.info:set("Re-Authorize Voice request")
            subtree:add(buf(start_i+2,2), "Re-Authorize Voice request: " .. buf(start_i+2,2))
	    
	    for i = 1,modo do
                if buf(start_i+i, 4):uint() == 983044 then 
                    subtree:add(buf(start_i+i+4,4), "ConversationTime: " .. buf(start_i+i+4,4):uint())
                end
	    end

	    
        elseif mtype == 784 then
            pinfo.cols.info:set("Authorize Voice confirm")
            subtree:add(buf(start_i+2,2), "Authorire voice confirm: " .. buf(start_i+2,2))

            for i = 1,modo do
                if buf(start_i+i, 4):uint() == 4194305 then -- 00:40:00:01
                    if buf(start_i+i+4,1):uint() == 1 then
                        subtree:add(buf(start_i+i+4,1), "Charge: " .. buf(start_i+i+4,1):uint()):append_text(" Charging")
                    elseif buf(start_i+i+4,1):uint() == 0 then
                        subtree:add(buf(start_i+i+4,1), "Charge: " .. buf(start_i+i+4,1):uint()):append_text(" No Charge")                 
                    end
                end
                       
                if buf(start_i+i, 4):uint() == 1835012 then -- 00:1c:00:04
                    subtree:add(buf(start_i+i+4,4), "MaxVolume: " .. buf(start_i+i+4,4):uint())
                end
            
                if buf(start_i+i, 4):uint() == 1179649 then -- 00:12:00:01  
                    if buf(start_i+i+4,1):uint() == 1 then
                        subtree:add(buf(start_i+i+4,1), "Disconnect: " .. buf(start_i+i+4,1):uint()):append_text(" True")
                    elseif buf(start_i+i+4,1):uint() == 0 then
                        subtree:add(buf(start_i+i+4,1), "Disconnect: " .. buf(start_i+i+4,1):uint()):append_text(" False")
                    end
                end
     
                if buf(start_i+i, 4):uint() == 4259841 then -- 00:41:00:01
                    if buf(start_i+i+4,1):uint() == 1 then
                        subtree:add(buf(start_i+i+4,1), "FurnishChargingInformation: " .. buf(start_i+i+4,1):uint()):append_text(" True")
                    elseif buf(start_i+i+4,1):uint() == 0 then
                        subtree:add(buf(start_i+i+4,1), "FurnishChargingInformation: " .. buf(start_i+i+4,1):uint()):append_text(" False")
                    end
                end
            end

	    
        elseif mtype == 1040 then
            pinfo.cols.info:set("Authorize Voice reject")
            subtree:add(buf(start_i,2), "Authorize voice reject: " .. buf(start_i,2))

            for i = 1, modo do         
                if buf(start_i+i, 4):uint() == 1245188 then -- 00:13:00:04
		    local error = buf(start_i+i+4,4)
                    err_handler(error)
                end
		
                if buf(start_i+i, 4):uint() == 2490372 then -- 00:26:00:04
                    local rel = buf(start_i+i+4, 4)
                    rc_handler(rel)
                end
            end        


        elseif mtype == 1296 then
            pinfo.cols.info:set("End Voice request")
            subtree:add(buf(2,2), "End voice request: " .. buf(2,2))
            local Endreason = buf(32,1):uint()
            if Endreason == 00 then
                subtree:add(buf(32,1), "Edndreason OK (0) " .. buf(32,1))      
            else
                subtree:add(buf(32,1), "End reason " .. buf(32,1))
            end
             
            for i = 1,modo do         
                if buf(start_i+i, 4):uint() == 262148 then -- 00:04:00:04
                    subtree:add(buf(start_i+i+4,4), "CallAttemptElapsedTime: " .. buf(start_i+i+4,4):uint())
                end
   
                if buf(start_i+i, 4):uint() == 917527 then -- 00:0e:00:17   
                    subtree:add(buf(start_i+i+4,23), "CallStopTime: " .. buf(start_i+i+4,23):string())
                end
     
                if buf(start_i+i, 4):uint() == 327684 then -- 00:05:00:04
                    subtree:add(buf(start_i+i+4,4), "CallConnectedElapsedTime: " .. buf(start_i+i+4,4):uint())
                end

                if buf(start_i+i, 4):uint() == 2490372 then -- 00:26:00:04 
                    local rel = buf(start_i+i+4, 4)
                    rc_handler(rel)
                end
            end
	
	
        elseif mtype == 1552 then
            pinfo.cols.info:set("End Voice ack")
            subtree:add(buf(start_i+2,2), "End voice ack: " .. buf(start_i+2,2))
                
            for i = 1,modo do     
                if buf(start_i+i, 4):uint() == 1245188 then -- 00:13:00:04
		    local error = buf(start_i+i+4,4)
                    err_handler(error)
                end
            end

	    
        elseif mtype == 304 then
            pinfo.cols.info:set("Authorize SMS request")
            subtree:add(buf(2,2), "Authorize sms request: " .. buf(2,2))
            subtree:add(buf(32,4), "ServiceKey: " .. buf(32,4):uint())

            for i = 1,modo do 
                if buf(start_i+i, 4):uint() == 1048587 then
                    subtree:add(buf(start_i+i+4, 11), "DestinationRoutingNumber: " .. buf(start_i+i+4, 11):string())
                end        
            
                if buf(start_i+i, 4):uint() == 655371 then -- 00:0a:00:0b
                    subtree:add(buf(start_i+i+4, 11), "CallingPartyNumber: " .. buf(start_i+i+4, 11):string())
                end
            
                if buf(start_i+i, 4):uint() == 3014667 then
                    subtree:add(buf(start_i+i+4, 11), "SMSCAddressNumber: " .. buf(start_i+i+4, 11):string())
                end
            
                if buf(start_i+i, 4):uint() == 1507343 then -- 00:17:00:0f
                    subtree:add(buf(start_i+i+4,15), "IMSI: " .. buf(start_i+i+4, 15):string())
                end
            
                if buf(start_i+i, 4):uint() == 3145736 then -- 00:30:00:08
		    local tz = start_i+i
                    tz_handler(tz)
                end
              
                if buf(start_i+i, 4):uint() == 3604491 then
                    subtree:add(buf(start_i+i+4,11), "VLRAddressNumber: " .. buf(start_i+i+4, 11):string())
                end

                if buf(start_i+i, 4):uint() == 1638422 then -- 00:19:00:16
                    subtree:add(buf(start_i+i+4,22), "LocationInformationMSC: " .. buf(start_i+i+4, 22))
                end
            end
	    
            
        elseif mtype == 560 then
            pinfo.cols.info:set("Authorize SMS confirm")
            subtree:add(buf(start_i,2), "Authorize sms confirm: " .. buf(start_i,2))
            
            for i = 1,modo do
                if buf(start_i+i, 4):uint() == 4194305 then -- 00:40:00:01
                    if buf(start_i+i+4,1):uint() == 1 then
                        subtree:add(buf(start_i+i+4,1), "Charge: " .. buf(start_i+i+4,1):uint()):append_text(" Charging")
                    elseif buf(start_i+i+4,1):uint() == 0 then
                        subtree:add(buf(start_i+i+4,1), "Charge: " .. buf(start_i+i+4,1):uint()):append_text(" No Charge")                 
                    end
                end
       
                if buf(start_i+i, 4):uint() == 4259841 then -- 00:41:00:01
                    if buf(start_i+i+4,1):uint() == 1 then
                        subtree:add(buf(start_i+i+4,1), "FurnishChargingInformation: " .. buf(start_i+i+4,1):uint()):append_text(" True")
                    elseif buf(start_i+i+4,1):uint() == 0 then
                        subtree:add(buf(start_i+i+4,1), "FurnishChargingInformation: " .. buf(start_i+i+4,1):uint()):append_text(" False")
                    end
                end
            end

	    
        elseif mtype == 816 then
            pinfo.cols.info:set("Authorize SMS reject")
            subtree:add(buf(start_i,2), "Authorize SMS reject: " .. buf(start_i,2))

            for i = 1, modo do         
                if buf(start_i+i, 4):uint() == 1245188 then -- 00:13:00:04
		    local error = buf(start_i+i+4,4)
		    err_handler(error)
		end

                if buf(start_i+i, 4):uint() == 2621444 then -- 00:28:00:04
		    local rel = buf(start_i+i+4,4)
		    if rel:uint() == 21 then
		        subtree:add(rel, "ReleaseCauseSMS: " .. rel:uint()):append_text(" Short message transfer rejected (21)")						
		    else
		        rc_handler(rel)
		    end
                end
            end   			
	    

        elseif mtype == 1072 then
            pinfo.cols.info:set("End SMS request")
            subtree:add(buf(2,2), "End sms request: " .. buf(2,2))
              
            for i = 1,modo do         
                if buf(start_i+i, 4):uint() == 3801089 then -- 00:26:00:04 
                    local endreason = buf(start_i+i+4, 1):uint()
                    if endreason == 0 then
                        subtree:add(buf(start_i+i+4,1), "EndReason: " .. buf(start_i+i+4,1):uint()):append_text(" Ok (0)")
                    else           
                        subtree:add(buf(start_i+i+4,1), "EndReason: " .. buf(start_i+i+4,1):uint())
                    end
                end
                     
                if buf(start_i+i, 4):uint() == 3080193 then 
                    local smsstatus = buf(start_i+i+4, 1):uint()
                    if smsstatus == 0 then
                        subtree:add(buf(start_i+i+4,1), "SMSStatus: " .. buf(start_i+i+4,1):uint()):append_text(" Submitted (0x00)")
                    else           
                        subtree:add(buf(start_i+i+4,1), "SMSStatus: " .. buf(start_i+i+4,1):uint())
                    end
                end
            end    
	    
            
        elseif mtype == 1328 then
            pinfo.cols.info:set("End SMS ack")
            subtree:add(buf(2,2), "End sms ack: " .. buf(2,2))
	    
            for i = 1,modo do         
                if buf(start_i+i, 4):uint() == 1245188 then -- 00:13:00:04
		    local error = buf(start_i+i+4,4)
                    err_handler(error)
                end
            end
                
        else
            pinfo.cols.info:set("Unknown type")
            subtree:add(buf(start_i+2,2), "Unknown type: hex: " .. buf(start_i+2,2), "little Indian: " .. buf(start_i+2,2):le_uint())
        end

	    
        subtree:add(" ") --  add empty strind to separate messages

        len_i = len_i + len
        start_i = start_i + len
        length = length - len

    end 
end

local tcp_dissector_table = DissectorTable.get("tcp.port") 
dissector = tcp_dissector_table:get_dissector(28000) 
tcp_dissector_table:add(28000, BRT)