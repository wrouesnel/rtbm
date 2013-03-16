/*
 *  This file is part of RTBM, Real-Time Bandwidth Monitor.
 *
 *  RTBM, Real-Time Bandwidth Monitor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  RTBM, Real-Time Bandwidth Monitor is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with RTBM, Real-Time Bandwidth Monitor.  If not, see <http://www.gnu.org/licenses/>.
 */

function removeOldEntries(host, ranking, ticksToHold){
	if (host['data'].length > ticksToHold) {
		var noTicksToRemove = host['data'].length - ticksToHold
		var counter
		for (counter = 0 ; counter < noTicksToRemove ; counter++)
			ranking[host.label] -= host['data'][counter][1]
		host['data'].splice(0, noTicksToRemove)
	}
}

function initAggregated(data, ranking){
	data.push({"label":"aggregated","data":[]});
	ranking["aggregated"] = 0
}

function copyExistingEntry(src, dst, ranking, aggregated, time){
	if (src[dst.label] === undefined) {
		if (dst.label == "aggregated")
			return
		val = 0
	} else {
		val = src[dst.label]
		ranking[dst.label] += val
		aggregated.value += val
	}
	dst['data'].push([time, val]);
	delete src[dst.label] // remove entry from array
}

function copyData(data, jsonData, ranking, time, ticksToHold){
	var aggregated = new Object()
	aggregated.value = 0
	//create aggregated for this cycle
	for (var counter = 0 ; counter < data.length ; counter++){
		copyExistingEntry(jsonData, data[counter], ranking, aggregated, time);
		removeOldEntries(data[counter], ranking, ticksToHold)
	}

	//Process the new ones
	for(var ip in jsonData){
		val = jsonData[ip]
		ranking[ip] = val
		aggregated.value += val
		data.push({"label":ip,"data":[[time, val]]});
	}
	if (data[0].label != "aggregated")
		alert("bug!")
	data[0]['data'].push([time, aggregated.value])
	ranking["aggregated"] += aggregated.value


}

function xAxisLabel (val){
	var date = new Date(val*1000);
	return date.getHours() + ':' + date.getMinutes() + ':' + date.getSeconds();
}

function yAxisLabel (val){
	return (val*8/1024) + 'Kbps'; //We get the size in kbps
}

function extractTop(data, noToShow){
	var counterTop
	if (data.length < noToShow)
		counterTop=data.length
	else 
		counterTop=noToShow;
	var dataTop = []
	for (var counter = 0 ; counter < counterTop ; counter++){
		dataTop.push(data[counter])
	}
	return dataTop;
}

function orderData(data, ranking){
	data.sort(function(a,b){return ranking[b.label]-ranking[a.label];});
}

function talkToGraph(){
	if ($('graphButton').value == "Unpause")
		$('graphButton').value = "Pause"
	else 
		$('graphButton').value = "Unpause"
}

function showFullRanking(data, ranking, destination){
	var num = ranking["aggregated"]/1024/1024;
	destination.innerHTML = "<strong>Total: " + num.toFixed(2) + "Mb</strong><br><br>";
	for (var counter = 1 ; counter < data.length ; counter++){ // start on 1 to skip the aggregated
		num = ranking[data[counter].label]/1024/1024;
		destination.innerHTML += counter + ". " + data[counter].label + ": " + num.toFixed(2) + "Mb<br>";
	}

}

document.observe('dom:loaded', function () {
	var time = 0
	var noToShow = 6
	var ticksToHold = 300
	var cycle_time = 1 //Fetch new data every second.
	var gSettings = {
		legend: {
			position: 'sw', // => position the legend 'south-west'.
			backgroundColor: '#D2E8FF' // => a light blue background color.
		},
		xaxis:{
			noTicks: 10,
			tickFormatter: xAxisLabel
		},
		yaxis:{
			noTicks: 10,
			tickFormatter: yAxisLabel
		},
		colors: [
			"black",
			"red",
			"blue",
			"orange",
			"purple",
			"green"
		], 
		mouse:{
			track: true,
			sensibility: 5, // => distance to show point get's smaller
			trackFormatter: function(obj){ return xAxisLabel(obj.x) +'=' + yAxisLabel(obj.y); }
		},
		HtmlText: false
	}

	var dataOutgoing = []
	var dataIncoming = []
	var rankingOutgoing = new Object() //Keys+Values
	var rankingIncoming = new Object() //Keys+Values

	// add the aggregated bandwidth
	initAggregated(dataOutgoing, rankingOutgoing)
	initAggregated(dataIncoming, rankingIncoming)
	new PeriodicalExecuter(function (pe) {
		new Ajax.Request('stats.json', {
			onSuccess: function (response) {
				if (200 == response.status) {
					var json = JSON.parse(response.responseText)
					if (json['time'] != time){
						document.title = json['iface'] + " - RTBM, Real-Time Bandwidth Monitor" 
						time = json['time']
						var jsonOutgoing = json['outgoing']
						var jsonIncoming = json['incoming']
						
						//Process from the list of what we already have:
						copyData(dataOutgoing, jsonOutgoing, rankingOutgoing, time, ticksToHold)
						copyData(dataIncoming, jsonIncoming, rankingIncoming, time, ticksToHold)

						// sort 
						orderData(dataOutgoing, rankingOutgoing)
						orderData(dataIncoming, rankingIncoming)

						if ($('graphButton').value == "Pause"){
							var fOutgoing = Flotr.draw($('outgoing'), extractTop(dataOutgoing, noToShow), gSettings);
							var fIncoming = Flotr.draw($('incoming'), extractTop(dataIncoming, noToShow), gSettings);
						}
						$('nifdrop').innerHTML = json['nifdrop'];
						$('ndrop').innerHTML = json['ndrop'];
						$('nrecv').innerHTML = json['nrecv'];
						showFullRanking(dataOutgoing, rankingOutgoing, $('rankingOutgoing'))
						showFullRanking(dataIncoming, rankingIncoming, $('rankingIncoming'))
					} 
// 					else {
// 						var firstStoredTime = dataDownstream[0]['data'][0][0]//the first entry in the dataDownstream will always be the aggregated. We take the time of the first data entry for the aggregated
// 						if (time - firstStoredTime > cycle_time*ticksToHold*1.5) {
// 							dataDownstream = []
// 							dataUpstream = []
// 							rankingDown = new Object() //Keys+Values
// 							rankingUp = new Object() //Keys+Values
// 							// add the aggregated bandwidth
// 							initAggregated(dataDownstream, rankingDown)
// 							initAggregated(dataUpstream, rankingUp)
// 						}
// 					}
				}
			}
		});

	}, cycle_time);
});
