#!groovy
//TODO: Figure out if people use these internal builds??
properties(
	[
		buildDiscarder(logRotator(numToKeepStr: '30')),
		parameters(
			[
				booleanParam(name: 'BUILD_PR', description: 'Trigger build on a PR', defaultValue: false),
			]
		)
	]
)

def isPRBuild() {
	env.JOB_BASE_NAME =~ '^PR-[0-9]*$'
}

stage("Trigger build job"){
	if (isPRBuild() && ! params.BUILD_PR) {
		currentBuild.result = 'SUCCESS'
		return
	}
	wrappedNode(label: "docker-edge&&x86_64", cleanWorkspace: true) {
		def buildBranch = env.BRANCH_NAME
		if (isPRBuild()) {
			buildBranch = env.BRANCH_NAME.toLowerCase().replace("-", "/")
		}
		build(
			job: 'release-packaging/ee-master',
			parameters: [
				[$class: 'StringParameterValue', name: 'DOCKER_EE_BRANCH', value: buildBranch],
				[$class: 'StringParameterValue', name: 'ARTIFACT_BUILD_TAG', value: env.BUILD_TAG],
				[$class: 'BooleanParameterValue', name: 'RELEASE_TO_STAGE', value: true],
				[$class: 'BooleanParameterValue', name: 'RELEASE_TO_PROD', value: false],
			],
			wait: true
		)
	}
}
