import { confirm, input, select, Separator  } from "@inquirer/prompts";
import { PipelineSourceOptions } from "./options";
import {
	SecretsManagerClient,
	CreateSecretCommand,
	GetSecretValueCommand,
	PutSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { BOLD, RESET } from "../util/textStyles"

type secretsManagerError = {
	$fault: string;
	$metadata: {
		httpStatusCode: number;
		requestId: string;
		extendedRequestId: string | undefined;
		cfId: string | undefined;
		attempts: number;
		totalRetryDelay: number;
	};
	__type: string;
};

const getAwsSecretValue = async (name: string) => {
	const client = new SecretsManagerClient();
	try {
		const data = await client.send(
			new GetSecretValueCommand({ SecretId: name })
		);
		return data.SecretString;
	} catch (err) {
		const error: secretsManagerError = err as secretsManagerError;
		if (error.__type === "ResourceNotFoundException") {
			console.log(`Secret not found in AWS SecretsManager: ${name}. `);
		} else {
			throw new Error(
				`Error getting secret in AWS SecretsManager: ${name}: ${err}`
			);
		}
	}
};

const updateAwsSecret = async (name: string, secret: string) => {
	const client = new SecretsManagerClient();
	try {
		const data = await client.send(
			new PutSecretValueCommand({
				SecretId: name,
				SecretString: secret,
			})
		);
		return data;
	} catch (err) {
		const error: secretsManagerError = err as secretsManagerError;
		if (error.__type === "ResourceNotFoundException") {
			throw new Error(`Secret not found in AWS SecretsManager: ${name}. `);
		} else {
			throw new Error(
				`Error updating secret in AWS SecretsManager: ${name}: ${err}`
			);
		}
	}
};

const createAwsSecret = async (name: string, secret: string) => {
	const client = new SecretsManagerClient();
	try {
		const data = await client.send(
			new CreateSecretCommand({
				Name: name,
				SecretString: secret,
				ForceOverwriteReplicaSecret: true,
			})
		);
		return data;
	} catch (err) {
		const error: secretsManagerError = err as secretsManagerError;
		if (error.__type === "ResourceExistsException") {
			throw new Error(`Secret already exists in AWS SecretsManager: ${name}. `);
		} else {
			throw new Error(
				`Error creating secret in AWS SecretsManager: ${name}: ${err}`
			);
		}
	}
};

const handleRepoToken = async (name: string) => {
	const secretValue = await getAwsSecretValue(name);

	if (secretValue) {
		const useExistingSecret = await confirm({
			message: `Secret ${name} already exists. Do you want to use it?`,
			default: true,
			theme,
		});

		if (useExistingSecret) {
			return secretValue;
		} else {
			const repoToken = await input({
				message: "Enter the repository token:",
				theme,
			});
			await updateAwsSecret(name, repoToken);
			return repoToken;
		}
	}
	const repoToken = await input({
		message: "Enter the repository token:",
		theme,
	});
	await createAwsSecret(name, repoToken);
	return repoToken;
};

type githubBranchInfo = {
	name: string;
	commit: {
		sha: string;
		url: string;
	};
	protected: boolean;
	protection: {
		enabled: boolean;
		required_status_checks: {
			enforcement_level: string;
			contexts: string[];
			checks: string[];
		};
	};
	protection_url: string;
};

// get the branches for a github repo without an API key
const getGithubBranches = async (
	repoOwner: string,
	repoName: string,
	token: string
): Promise<string[]> => {
	// get the branches for a github repo without an API key
	const url = `https://api.github.com/repos/${repoOwner}/${repoName}/branches`;
	const response = await fetch(url, {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	const jsonData = await response.json();
	if (Array.isArray(jsonData)) {
		const data: githubBranchInfo[] = jsonData;
		return data.map((branch: any) => branch.name);
	}
	console.log(jsonData);
	throw new Error("Unexpected response format");
};

type branchChoices = {
    name: string;
    value: string;
} | Separator;

const getGitHubReleaseBranches = async (
    repoOwner: string,
    repoName: string,
    token: string
): Promise<branchChoices[]> => {
    const releaseBranches = await getGithubBranches(repoOwner, repoName, token);
    releaseBranches.sort().reverse();

    const choices: branchChoices[] = [];
    let currentGroup = "";

    releaseBranches.forEach((branch: string) => {
        const slashIndex = branch.indexOf('/');
        let group = "";
        let name = branch;

        if (slashIndex !== -1) {
            group = branch.substring(0, slashIndex);
            name = branch;
        }

        if (group !== currentGroup) {
            choices.push(new Separator(`${BOLD} # ${group || "other"} ${RESET}`));
            currentGroup = group;
        }

        choices.push({
            name: name,
            value: branch,
        });
    });

    return choices;
};

const canTokenRepoHook = async (token: string, repoOwner: string, repoName: string): Promise<boolean> => {
	// First check if the token has repo_hook scope
	const authUrl = `https://api.github.com/authorizations`;
	const authResponse = await fetch(authUrl, {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	const scopes = authResponse.headers.get("x-oauth-scopes");
	
	// If the token doesn't even have repo_hook scope, it definitely can't create hooks
	if (!scopes || !scopes.includes("repo_hook")) {
		if (scopes && scopes.includes("public_repo")) {
			// public_repo includes repo hook permissions for public repositories
			// We should check if the repository is public
			const repoUrl = `https://api.github.com/repos/${repoOwner}/${repoName}`;
			const repoResponse = await fetch(repoUrl, {
				headers: {
					Authorization: `Bearer ${token}`,
				},
			});
			
			if (repoResponse.ok) {
				const repoData = await repoResponse.json();
				return !repoData.private; // Can create hooks if repo is public
			}
			return false;
		}
		return false;
	}
	
	// Even with repo_hook, verify we have appropriate permissions on the specific repo
	const repoUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/hooks`;
	try {
		const repoResponse = await fetch(repoUrl, {
			method: 'GET',
			headers: {
				Authorization: `Bearer ${token}`,
			},
		});
		
		// Status 200 means we can list hooks, which indicates we can create them
		// Status 404 might mean repo doesn't exist or no hooks yet, but shouldn't happen with valid repo
		// Status 403 means we don't have permission
		return repoResponse.status === 200;
	} catch (error) {
		console.log(`Error checking repository hook permissions: ${error}`);
		return false;
	}
};

const usePeriodicChecksInCodepipeline = (
	owner: string,
	name: string
): boolean => {
	if (owner === "aws-samples" && name === "document-translation") {
		console.log("Pointed at upstream. Using periodic checks in codepipeline");
		return true;
	} else {
		console.log("Pointed at fork. Using repo hooks to codepipeline");
		return false;
	}
};

const theme = {
	prefix: "Pipeline - Source: ",
};

const showInstruction = () => {
	console.log(`
${BOLD}# Pipeline - Source Configuration${RESET}
GitHub is used at the source code repository.
Requirements: 1) GitHub Account. 2) GitHub Access Token.
If using the upstream AWS-Samples respository then a classic token with "public_repo" and no expiration will work. 
Prerequisite: https://aws-samples.github.io/document-translation/docs/shared/prerequisites/github-token/
	`);
};

export const getPipelineSourceOptions = async (
	instanceName: string
): Promise<PipelineSourceOptions> => {
	showInstruction();

	let answers: PipelineSourceOptions = {
		pipeline: {
			source: {
				repoOwner: await input({
					message: "Repo Owner (github.com/<OWNER>/<NAME>)",
					required: true,
					default: "aws-samples",
					theme,
				}),
				repoName: await input({
					message: "Repo Name (github.com/<OWNER>/<NAME>)",
					required: true,
					default: "document-translation",
					theme,
				}),
				repoBranch: "",
				repoHookEnable: false,
				repoPeriodicChecksEnable: true,
				repoTokenName: "",
			},
		},
	};

	const repoToken = await handleRepoToken(
		`doctran-${instanceName}-oauth-token`
	);

	answers.pipeline.source.repoBranch = await select({
		message: "Release",
		pageSize: 30,
		choices: await getGitHubReleaseBranches(
			answers.pipeline.source.repoOwner,
			answers.pipeline.source.repoName,
			repoToken
		),
		theme,
	});

	answers.pipeline.source.repoPeriodicChecksEnable =
		usePeriodicChecksInCodepipeline(
			answers.pipeline.source.repoOwner,
			answers.pipeline.source.repoName
		);
	
	// Pass the repo owner and name to check if hook can be created for this specific repo
	answers.pipeline.source.repoHookEnable = await canTokenRepoHook(
		repoToken,
		answers.pipeline.source.repoOwner,
		answers.pipeline.source.repoName
	);

	return answers;
};
