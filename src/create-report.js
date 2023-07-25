import { js2xml } from 'xml-js'

import { createDisconnectedDataEntry } from './disconnected.js'

export default async function(findings) {
	const moreThanFourEdges = findings.moreThanFourEdges
	const suspiciousAngle = findings.suspiciousAngle
	const fourVerticesNoCrossing = findings.fourVerticesNoCrossing
	const disconnectedTracks = findings.disconnectedTracks

	const entriesMoreThanFourEdges = moreThanFourEdges.map(error => {
		const dataEntry = {
			_attributes: {
				class: '12347',
				subclass: '1',
			},
			location: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
				},
			},
			node: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
					id: error.nodeId,
					user: error.user,
					version: error.version,
				},
			},
			text: {
				_attributes: {
					lang: 'en',
					value: '4 vertices and no crossing',
				},
			},
		}
		return dataEntry
	})

	const entriesSuspiciousAngle = suspiciousAngle.map(error => {
		const dataEntry = {
			_attributes: {
				class: '12345',
				subclass: '1',
			},
			location: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
				},
			},
			node: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
					id: error.nodeId,
					user: error.user,
					version: error.version,
				},
			},
			text: {
				_attributes: {
					lang: 'en',
					value: 'suspicious angle on way: ' + error.angle,
				},
			},
		}
		return dataEntry
	})

	const entriesFourVerticesNoCrossing = fourVerticesNoCrossing.map(error => {
		const dataEntry = {
			_attributes: {
				class: '12346',
				subclass: '1',
			},
			location: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
				},
			},
			node: {
				_attributes: {
					lat: error.lat,
					lon: error.lon,
					id: error.nodeId,
					user: error.user,
					version: error.version,
				},
			},
			text: {
				_attributes: {
					lang: 'en',
					value: 'more than four edges on node: ' + error.edgeCount,
				},
			},
		}
		return dataEntry
	})

	//const entriesDisconnectedTracks = disconnectedTracks.map(createDisconnectedDataEntry)

	const options = { compact: true, ignoreComment: true, spaces: 4 }
	const date = new Date()
	const data = {
		_declaration: { _attributes: { version: '1.0', encoding: 'utf-8' } },
		analysers: {
			analyser: {
				_attributes: {
					timestamp: date,
				},
				class: [{
					_attributes: {
						id: 12345,
						level: 2,
						item: 1010,
					},
					classtext: {
						_attributes: {
							lang: 'en',
							title: 'way angles',
						},
					},
				},
				{
					_attributes: {
						id: 12346,
						level: 2,
						item: 1020,
					},
					classtext: {
						_attributes: {
							lang: 'en',
							title: 'too many edges',
						},
					},
				},
				{
					_attributes: {
						id: 12347,
						level: 2,

						item: 1020,
					},
					classtext: {
						_attributes: {
							lang: 'en',
							title: '4 edges no crossing',
						},
					},
				},
				{
					_attributes: {
						id: 12348,
						level: 2,

						item: 1030,
					},
					classtext: {
						_attributes: {
							lang: 'en',
							title: 'disconnected tracks',
						},
					},
				},
				],
				error: [
					...entriesFourVerticesNoCrossing,
					...entriesSuspiciousAngle,
					...entriesMoreThanFourEdges,
					//...entriesDisconnectedTracks,
				],
			},
			_attributes: {
				timestamp: date.toISOString(),
			},
		},
	}
	const result = js2xml(data, options)
	process.stdout.write(result + '\n')
}
