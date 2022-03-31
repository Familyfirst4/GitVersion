﻿using GitVersion.Infrastructure;

namespace GitVersion.Project;

[Command("project", typeof(OutputSettings), "Outputs version to project")]
public class OutputProjectCommand : Command<OutputProjectSettings>
{
    private readonly ILogger logger;
    private readonly IService service;

    public OutputProjectCommand(ILogger logger, IService service)
    {
        this.logger = logger;
        this.service = service;
    }

    public override Task<int> InvokeAsync(OutputProjectSettings settings)
    {
        var value = service.Call();
        logger.LogInformation($"Command : 'output project', LogFile : '{settings.LogFile}', WorkDir : '{settings.OutputDir}', InputFile: '{settings.InputFile}', Project: '{settings.ProjectFile}' ");
        return Task.FromResult(value);
    }
}