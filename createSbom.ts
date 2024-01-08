import axios, {AxiosRequestConfig} from "axios";
import fs from "fs";

// Add in API_KEY and ORG_ID. Currently this script will only get up to the first 100 projects in an organization, limiting projects found
// to the following types: maven, gradle, yarn, npm, pip, nuget. It will then call the Snyk API once more in order to generate the SBOM document 
// for each of these projects, writing to a new file in the same directory. 
const API_KEY = "";
const ORG_ID = "";

async function getSnykProjects(apiKey: string, orgId: string): Promise<string []> {
    const PROJECTS_URL = `https://api.snyk.io/rest/orgs/${orgId}/projects?version=2024-01-04~beta&types=maven%2Cgradle%2Cyarn%2Cnpm%2Cpip%2Cnuget%2Ccomposer&limit=100`;
    
    const headers = {
        Authorization: `token ${apiKey}`,
        'Content-Type': 'application/json',
    }; 

    const config: AxiosRequestConfig = {
        method: 'GET',
        url: PROJECTS_URL,
        headers: headers,
    }; 

    try {
        const response = await axios(config);
        const projects = response.data.data;
        return projects.map((project: { id: string; }) => project.id);
    } catch (error: unknown) {
        console.error('Error calling Snyk API:', error);
        throw error;
    }
}

async function createSBOMFromProjectIds(apiKey: string, orgId: string, projectIds: string[]): Promise<any> {
    const headers = {
        Authorization: `token ${apiKey}`,
        'Content-Type': 'application/json',
    }; 
    
    return await Promise.all(projectIds.map(async projectId => {
        const SBOM_URL = `https://api.snyk.io/rest/orgs/${orgId}/projects/${projectId}/sbom?version=2024-01-04%7Ebeta&format=cyclonedx1.4%2Bjson`;
        const config: AxiosRequestConfig = {
            method: 'GET',
            url: SBOM_URL,
            headers: headers,
        }; 
        
        try {
            const response = await axios(config);
            return {
                [projectId]: response.data
            };
        } catch (error: unknown) {
            console.log("error: ", error);
            throw error;
        }
    }))
}

const projectIds = await getSnykProjects(API_KEY, ORG_ID);
const sboms = await createSBOMFromProjectIds(API_KEY, ORG_ID, projectIds);
const date = new Date().toISOString();

await fs.writeFile(`sbom_${date}.json`, JSON.stringify(sboms), (err) => {
    if (err) throw err;
    console.log("Done");
});

