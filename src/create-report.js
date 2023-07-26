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
				class: 3,
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
		}
		return dataEntry
	})

	const entriesSuspiciousAngle = suspiciousAngle.map(error => {
		const dataEntry = {
			_attributes: {
				class: 1,
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
			text: [
				{
					_attributes: {
						lang: 'en',
						value: 'Suspicious angle: ' + error.angle,
					}
				}, {
					_attributes: {
						lang: 'fr',
						value: 'Angle douteux: ' + error.angle,
					}
				}
			],
		}
		return dataEntry
	})

	const entriesFourVerticesNoCrossing = fourVerticesNoCrossing.map(error => {
		const dataEntry = {
			_attributes: {
				class: 2,
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
			text: [{
				_attributes: {
					lang: 'en',
					value: 'Number of edges on railway node: ' + error.edgeCount,
				}
			},{
				_attributes: {
					lang: 'fr',
					value: 'Nombre d’arcs sur le nœud ferroviaire: ' + error.edgeCount,
				}
			}],
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
					timestamp: date.toISOString(),
				},
				class: [{
					_attributes: {
						id: 1,
						level: 2,
						item: 1301,
						tags: ['geom', 'railway'],
						source: 'https://github.com/osrd-project/fixOurRail',
					},
					classtext: [
						{
							_attributes: {
								lang: 'en',
								title: 'Suspicious way angles',
								detail: 'Trains cannot take sharp angles. This might indicate missing nodes on the way or misplaces nodes.'
							},
						},
						{
							_attributes:{
								lang: 'fr',
								title: 'Angles de way ferroviaire douteux',
								detail: 'Les trains ne peuvent pas prendre d’angle serrés. Cela peut indiquer un manque de nœuds le long du way, ou un nœud mal placé'
							}
						}
					],
				},
				{
					_attributes: {
						id: 2,
						level: 2,
						item: 1302,
						tags: ['railway'],
						source: 'https://github.com/osrd-project/fixOurRail',
					},
					classtext: [
						{
							_attributes: {
								lang: 'en',
								title: 'Too many edges at a rail switch',
								detail: 'Swiches usually allow only to go from on edge to two others. If there is more, it often means that two consecutive switches are merged into one.'
							}
						},
						{
							_attributes: {
								lang: 'fr',
								title: 'Trop d’arcs a un aiguillage ferroviaire',
								detail: 'Un aiguillage permet habituellement de passer d’un arc vers deux autres. S’il y en a plus, cela représente souvent deux aiguillages mappés comme un seul.'
							}
						}

					],
				},
				{
					_attributes: {
						id: 3,
						level: 2,
						tags: ['railway'],
						item: 1303,
						source: 'https://github.com/osrd-project/fixOurRail',
					},
					classtext: [
						{
							_attributes: {
								lang: 'en',
								title: '4 rail edges no crossing and no railway=railway_crossing',
								detail: 'When two rail tracks cross at level without a switch, it should be tagged as a crossing.',
								fix: 'Add the tag railway=railway_crossing on the common node (or a switch, bridge, tunnel).'
							}
						}, {
							_attributes: {
								lang: 'fr',
								title: '4 arcs ferrovaires et pas de tag railway=railway_crossing',
								detail: 'Lorsque deux voies ferrées se croisent sans aiguillage, il faut tagger le croisement à niveau.',
								fix: 'Ajouter le tag railway=railway_crossing sur le nœud en commun (ou une aiguille, pont ou tunnel).'
							}
						}
					],
				}],
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
