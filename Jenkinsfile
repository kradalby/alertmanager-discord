podTemplate(containers: [
    containerTemplate(name: 'docker', image: 'docker:19.03.6', command: 'cat', ttyEnabled: true),
    containerTemplate(
        name: 'sonarqube',
        image: 'cloudbees/java-build-tools:2.5.1',
        command: 'cat',
        ttyEnabled: true
    ),
  ],
  volumes: [
    hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock')
  ]
  ) {
    node(POD_LABEL) {
        def appName = "alertmanager-discord"
        def appFullName
        def revision
        def message
        def repoURL
        
        stage('Checkout') {
            def scmVars = checkout([
                $class: 'GitSCM',
                branches: scm.branches,
                extensions: scm.extensions + [
                    [
                        $class: 'AuthorInChangelog'
                    ],
                    [
                        $class: 'ChangelogToBranch',
                        options: [
                            compareRemote: 'origin',
                            compareTarget: 'master'
                        ]
                    ]
                ],
                userRemoteConfigs: scm.userRemoteConfigs
                ])
            appFullName = "${appName}:${scmVars.GIT_COMMIT}"
            revision = "${scmVars.GIT_COMMIT}"
            repoURL = "${scmVars.GIT_URL}"
            echo repoURL
            message = sh(returnStdout: true, script: "git log --oneline -1 ${revision}")
        }

        // Build and push the image and notify via Discord only on PR merge to main.
        if (env.BRANCH_NAME == 'master') {
            stage('Build Docker Image') {
                container('docker') {
                    docker.withRegistry('https://107126629234.dkr.ecr.ap-southeast-1.amazonaws.com', 'ecr:ap-southeast-1:49feb1c9-1719-4520-aa17-67695b347b0e') {
                        script {
                            sh """docker build --network=host -f "Dockerfile" -t 107126629234.dkr.ecr.ap-southeast-1.amazonaws.com/${appFullName} ."""
                        }
                    }
                }
            }

            stage('Push Docker Image') {

                container('docker') {
                    docker.withRegistry('https://107126629234.dkr.ecr.ap-southeast-1.amazonaws.com', 'ecr:ap-southeast-1:49feb1c9-1719-4520-aa17-67695b347b0e	') {
                        script {
                            sh """docker push 107126629234.dkr.ecr.ap-southeast-1.amazonaws.com/${appFullName}"""
                        }
                    }
                }
            }

            stage('Notification') {
                discordSend description: "${message}", footer: "${appFullName}", result: currentBuild.currentResult, title: "$JOB_NAME", webhookURL: "$DISCORD_WEBHOOK"
            }
        }
    }
}