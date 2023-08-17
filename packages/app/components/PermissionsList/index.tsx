import z from "zod"
import { ChainId } from "@/app/chains"
import Flex from "@/ui/Flex"
import { Annotation, Target, reconstructPermissions } from "zodiac-roles-sdk"
import { Permission, Preset } from "./types"
import { OpenApiObject, zOpenApiObject, zPermission } from "./schema"
import PresetItem from "./PresetItem"
import { FunctionPermissionItem, TargetPermissionItem } from "./PermissionItem"

interface Props {
  targets: Target[]
  annotations: Annotation[]
  chainId: ChainId
}

const PermissionsList = async ({ targets, annotations, chainId }: Props) => {
  const allPermissions = reconstructPermissions(targets)
  const { presets, permissions } = await processAnnotations(
    allPermissions,
    annotations
  )

  return (
    <Flex direction="column" gap={1}>
      {presets.map((preset, i) => (
        <PresetItem key={`${preset.serverUrl}${preset.path}`} {...preset} />
      ))}

      {permissions.map((permission, i) =>
        "selector" in permission ? (
          <FunctionPermissionItem key={i} {...permission} />
        ) : (
          <TargetPermissionItem key={i} {...permission} />
        )
      )}
    </Flex>
  )
}

export default PermissionsList

/** Process annotations and return all presets and remaining unannotated permissions */
const processAnnotations = async (
  permissions: Permission[],
  annotations: Annotation[]
) => {
  // const presets = await Promise.all(annotations.map(resolveAnnotation))

  // const filteredPresets = presets.filter(Boolean).map((preset) => {
  //   // TODO remove all preset.permissions that are not included in `permissions`
  //   return preset
  // })
  const filteredPresets: Preset[] = []

  // TODO remove all permissions that are already included in any preset
  const filteredPermissions = permissions

  return { presets: filteredPresets, permissions: filteredPermissions }
}

const resolveAnnotation = async (
  annotation: Annotation
): Promise<Preset | null> => {
  try {
    const [permissions, schema] = await Promise.all([
      fetch(annotation.url)
        .then((res) => res.json())
        .then(z.array(zPermission).parse),
      fetch(annotation.schema)
        .then((res) => res.json())
        .then(zOpenApiObject.parse),
      ,
    ])

    const { serverUrl, path } = resolveAnnotationPath(
      annotation.url,
      schema,
      annotation.schema
    )

    // TODO resolve annotation.url using the schema and produce the following object:
    const operation = schema.paths[path].get // TODO: instead of path we must use matching the path *pattern*
    if (!operation) {
      throw new Error(
        `No get operation found for ${annotation.url}, using schema ${annotation.schema}`
      )
    }

    return {
      permissions,
      apiInfo: schema.info,
      path,
      serverUrl,
      operation,
    }
  } catch (e) {
    console.error(
      `Error resolving annotation ${annotation.url} with schema ${annotation.schema}`,
      e
    )
  }

  return null
}

/** Returns the annotation's path relative to the API server's base URL */
const resolveAnnotationPath = (
  annotationUrl: string,
  schema: OpenApiObject,
  schemaUrl: string
) => {
  // Server urls may be relative, to indicate that the host location is relative to the location where the OpenAPI document is being served.
  // We resolve them to absolute urls.
  const serverUrls =
    schema.servers.length === 0
      ? ["/"]
      : schema.servers.map((server) => server.url)
  const absoluteServerUrls = serverUrls.map(
    (serverUrl) => new URL(serverUrl, schemaUrl).href
  )

  const matchingServerUrl = absoluteServerUrls.find((serverUrl) =>
    new URL(annotationUrl, serverUrl).href.startsWith(serverUrl)
  )

  if (!matchingServerUrl) {
    throw new Error(
      `Annotation url ${annotationUrl} is not within any server url declared in the schema ${schemaUrl}`
    )
  }

  return {
    serverUrl: matchingServerUrl,
    path: new URL(annotationUrl, matchingServerUrl).href.slice(
      matchingServerUrl.length
    ),
  }
}
